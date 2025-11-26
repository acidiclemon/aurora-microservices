#!/usr/bin/env groovy

node {
    docker.image('docker:27.2-dind')
          .inside('--privileged -v /var/run/docker.sock:/var/run/docker.sock -u 0') {

        properties([
            parameters([
                string(name: 'ECR_REGISTRY', defaultValue: "${ECR_REGISTRY}", description: 'ECR Registry URL (e.g., account.dkr.ecr.region.amazonaws.com)'),
                string(name: 'SERVICE_REPO', defaultValue: "${SERVICE_REPO}", description: 'Service Repository Name (e.g., aurora-microservices)'),
                string(name: 'AWS_REGION', defaultValue: "${AWS_REGION}", description: 'AWS Region'),
                string(name: 'SERVICE_NAME', defaultValue: 'adservice', description: 'Docker Service Name (e.g., adservice)')
            ])
        ])

        try {
            stage('Checkout') {
                checkout scm
            }

            stage('Checkov Scan') {
                sh 'docker pull bridgecrew/checkov:latest'
                docker.image('bridgecrew/checkov:latest').inside('--entrypoint=""') {
                    sh 'mkdir -p checkov-results'
                    sh '''
                        checkov -d main/terraform/ \
                            --compact \
                            --soft-fail \
                            --skip-download \
                            --download-external-modules true \
                            --framework terraform \
                            --output-file-path checkov-results/ \
                            --output sarif \
                    '''
                }
            }

            stage('Scan for Secrets') {
                sh 'git config --global --add safe.directory ${WORKSPACE}'

                sh '''
                    apk add --no-cache curl tar gzip
                    curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.29.0/gitleaks_8.29.0_linux_x64.tar.gz \
                        | tar -xzf - gitleaks
                    chmod +x gitleaks
                '''

                try {
                    sh './gitleaks git -v --exit-code 1 --redact=100 --report-path leaks.json .'
                } catch (err) {
                    archiveArtifacts artifacts: 'leaks.json', allowEmptyArchive: true, fingerprint: true
                    error 'Pipeline failed: Secrets detected in code. Review leaks.json for details.'
                }
                archiveArtifacts artifacts: 'leaks.json', allowEmptyArchive: true, fingerprint: true
            }

            stage('Semgrep SAST Scan') {
                sh 'docker pull semgrep/semgrep:latest'
                docker.image('semgrep/semgrep').inside {
                    sh '''
                        git config --global --add safe.directory "$WORKSPACE"

                        if [ -n "${CHANGE_TARGET:-}" ]; then
                            git fetch --no-tags --depth=1 origin "${CHANGE_TARGET}:origin/${CHANGE_TARGET}"
                            export SEMGREP_BASELINE_REF="origin/${CHANGE_TARGET}"
                        elif [ "${BRANCH_NAME}" != "main" ]; then
                            git fetch --no-tags --depth=1 origin main:origin/main
                            export SEMGREP_BASELINE_REF=origin/main
                        else
                            unset SEMGREP_BASELINE_REF
                        fi

                        if [ "${BRANCH_NAME}" = "main" ]; then
                            semgrep ci --config auto --sarif-output=semgrep.sarif || true
                        else
                            semgrep ci --config auto --sarif-output=semgrep.sarif
                        fi
                    '''
                }
                archiveArtifacts artifacts: 'semgrep.sarif', allowEmptyArchive: true, fingerprint: true
            }

            stage('Setup') {
                sh 'apk add --no-cache aws-cli'
            }

            stage('Build') {
                sh """
                    docker build \
                        -f src/${params.SERVICE_NAME}/Dockerfile \
                        -t ${params.SERVICE_REPO}/${params.SERVICE_NAME}:latest \
                        src/${params.SERVICE_NAME}
                """
            }

            stage('Trivy Security Scan') {
              sh 'docker pull aquasec/trivy:latest'
              sh """
                  docker run --rm \
                  -v /var/run/docker.sock:/var/run/docker.sock \
                  -v \$HOME/.cache/trivy:/root/.cache/ \
                  aquasec/trivy image \
                  --scanners vuln,secret,misconfig \
                  --exit-code 1 \
                  --severity CRITICAL \
                  --ignore-unfixed \
                  ${params.SERVICE_REPO}/${params.SERVICE_NAME}:latest
                  """

            }

            stage('Push') {
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'aws-creds',
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
                    sh """
                        aws ecr get-login-password --region ${params.AWS_REGION} | \
                        docker login --username AWS --password-stdin ${params.ECR_REGISTRY}

                        docker tag ${params.SERVICE_REPO}/${params.SERVICE_NAME}:latest \
                                   ${params.ECR_REGISTRY}/${params.SERVICE_REPO}/${params.SERVICE_NAME}:latest

                        docker push ${params.ECR_REGISTRY}/${params.SERVICE_REPO}/${params.SERVICE_NAME}:latest

                        docker logout ${ECR_REGISTRY} || true
                    """
                }
            }

        } finally {
            stage('Publish Checkov Results') {
                recordIssues(
                    enabledForFailure: true,
                    tool: sarif(
                        pattern: 'checkov-results/results_sarif.sarif',
                        name: 'Checkov Security Scan',
                        id: 'checkov'
                    ),
                    qualityGates: [
                        [threshold: 0.1, type: 'TOTAL_ERROR', unstable: true],
                        [threshold: 0.1, type: 'TOTAL_HIGH', unstable: true],
                        [threshold: 3, type: 'TOTAL_NORMAL', unstable: true]
                    ],
                    healthy: 5,
                    unhealthy: 10
                )
            }

            stage('Publish Semgrep Results') {
                recordIssues(
                    enabledForFailure: true,
                    tool: sarif(
                        pattern: '**/semgrep.sarif',
                        name: 'Semgrep Security Scan',
                        id: 'semgrep'
                    ),
                    qualityGates: [
                        [threshold: 14, type: 'TOTAL_ERROR', unstable: false],
                        [threshold: 19, type: 'TOTAL_HIGH', unstable: false],
                        [threshold: 33, type: 'TOTAL_NORMAL', unstable: true]
                    ],
                    healthy: 50,
                    unhealthy: 100
                )
            }

            stage('Publish Semgrep SARIF report') {
                archiveArtifacts artifacts: 'semgrep.sarif', allowEmptyArchive: true, fingerprint: true
            }

            // TO DO Fix trivy build reports in build result!!!!!!!!!!!!!!!!!!!!!!!

            // stage('Publish Trivy Security Scan Results') {
            //     publishHTML([
            //       allowMissing: false,
            //       alwaysLinkToLastBuild: true,
            //       keepAll: true,
            //       reportDir: '',
            //       reportFiles: 'trivy-report.html',
            //       reportName: 'Trivy Vulnerability Report'
            //   ])
            // }

            sh 'chown -R 1000:1000 .' // fix perm issue with trivy

            stage('Cleanup') {
                sh """
                    docker rmi ${params.SERVICE_REPO}/${params.SERVICE_NAME}:latest \
                               ${params.ECR_REGISTRY}/${params.SERVICE_REPO}/${params.SERVICE_NAME}:latest || true
                """
                cleanWs(cleanWhenFailure: true, deleteDirs: true, disableDeferredWipeout: true)
            }
        }
    }
}
