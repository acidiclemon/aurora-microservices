#!/usr/bin/env groovy

def SERVICE_CHOICES = [
    'auto', 'all', 'none',
    'adservice', 'cartservice', 'checkoutservice', 'currencyservice',
    'emailservice', 'frontend', 'loadgenerator', 'paymentservice',
    'productcatalogservice', 'recommendationservice', 'shippingservice',
    'shoppingassistantservice'
]

node {
    docker.image('docker:27.2-dind')
          .inside('--privileged -v /var/run/docker.sock:/var/run/docker.sock -u 0') {

        properties([
            parameters([
                string(name: 'ECR_REGISTRY', defaultValue: "${ECR_REGISTRY}"),
                string(name: 'SERVICE_REPO', defaultValue: "${SERVICE_REPO}"),
                string(name: 'AWS_REGION', defaultValue: "${AWS_REGION}"),
                choice(name: 'SERVICE_NAME', choices: SERVICE_CHOICES, description: 'Service to build')
            ])
        ])

        def selected = params.SERVICE_NAME
        def servicesToBuild = []

        if (selected == 'all') {
            servicesToBuild = SERVICE_CHOICES.drop(3)
        } else if (selected == 'none') {
            servicesToBuild = []
        } else if (selected == 'auto') {
            def base = env.CHANGE_TARGET ?: 'main'
            def changed = sh(
                script: "git diff --name-only origin/${base} -- src/ | awk -F'/' 'NF>1 {print \$2}' | sort -u || true",
                returnStdout: true
            ).trim().tokenize('\n')

            servicesToBuild = changed.findAll { it in SERVICE_CHOICES }

            if (servicesToBuild.isEmpty()) {
                echo "No service directories modified → skipping build/scan/push"
            } else {
                echo "Auto-detected services: ${servicesToBuild.join(', ')}"
            }
        } else {
            servicesToBuild = [selected]
        }

        try {
            stage('Checkout') { checkout scm }

            stage('Checkov Scan') {
                sh 'docker pull bridgecrew/checkov:latest'
                docker.image('bridgecrew/checkov:latest').inside('--entrypoint=""') {
                    sh 'mkdir -p checkov-results'
                    sh '''
                        checkov -d main/terraform/ --compact --soft-fail --skip-download \
                            --download-external-modules true --framework terraform \
                            --output-file-path checkov-results/ --output sarif
                    '''
                }
            }

            stage('Scan for Secrets') {
                sh 'git config --global --add safe.directory ${WORKSPACE}'
                sh '''
                    apk add --no-cache curl tar gzip
                    curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.29.0/gitleaks_8.29.0_linux_x64.tar.gz | tar -xzf - gitleaks
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

            stage('Setup') { sh 'apk add --no-cache aws-cli' }

            if (servicesToBuild.size() > 0) {
                servicesToBuild.each { service ->
                    stage("Build ${service}") {
                        def dockerfilePath = sh(
                            script: "find src/${service} -name Dockerfile -type f | head -1 || echo ''",
                            returnStdout: true
                        ).trim()

                        if (!dockerfilePath) {
                            error "Dockerfile not found for service: ${service}"
                        }

                        def buildContext = dockerfilePath.replaceAll('/Dockerfile$', '')

                        sh """
                            docker build -f ${dockerfilePath} -t ${params.SERVICE_REPO}/${service}:latest ${buildContext}
                        """
                    }

                    stage("Trivy Scan ${service}") {
                        sh 'docker pull aquasec/trivy:latest'
                        sh """
                            docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v \$HOME/.cache/trivy:/root/.cache/ \
                            aquasec/trivy image --scanners vuln,secret,misconfig \
                            --exit-code 1 --severity CRITICAL --ignore-unfixed \
                            ${params.SERVICE_REPO}/${service}:latest
                        """
                    }

                    stage("Push ${service}") {
                        withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-creds',
                            accessKeyVariable: 'AWS_ACCESS_KEY_ID', secretKeyVariable: 'AWS_SECRET_ACCESS_KEY']]) {
                            sh """
                                aws ecr get-login-password --region ${params.AWS_REGION} |
                                docker login --username AWS --password-stdin ${params.ECR_REGISTRY}
                                docker tag ${params.SERVICE_REPO}/${service}:latest ${params.ECR_REGISTRY}/${params.SERVICE_REPO}/${service}:latest
                                docker push ${params.ECR_REGISTRY}/${params.SERVICE_REPO}/${service}:latest
                                docker logout ${ECR_REGISTRY} || true
                            """
                        }
                    }
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

            archiveArtifacts artifacts: 'semgrep.sarif, leaks.json', allowEmptyArchive: true

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

            sh 'chown -R 1000:1000 .' //fix perm issue with trivy

            stage('Cleanup') {
                if (servicesToBuild.size() > 0) {
                    def images = servicesToBuild.collect {
                        "${params.SERVICE_REPO}/${it}:latest ${params.ECR_REGISTRY}/${params.SERVICE_REPO}/${it}:latest"
                    }.join(' ')
                    sh "docker rmi ${images} || true"
                }
                cleanWs(cleanWhenFailure: true, deleteDirs: true, disableDeferredWipeout: true)
            }
        }
    }
}
