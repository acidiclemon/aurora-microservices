#!/usr/bin/env groovy

node {
    docker.image('docker:27.2-dind')
          .inside('--privileged -v /var/run/docker.sock:/var/run/docker.sock -u 0') {

        properties([
            parameters([
                string(name: 'ECR_REGISTRY', defaultValue: "${ECR_REGISTRY}", description: 'ECR Registry URL (e.g., account.dkr.ecr.region.amazonaws.com)'),
                string(name: 'SERVICE_REPO', defaultValue: "${SERVICE_REPO}", description: 'Service Repository Name (e.g., aurora-microservices)'),
                string(name: 'AWS_REGION', defaultValue: "${AWS_REGION}", description: 'AWS Region'),
                string(name: 'GITHUB_REPO', defaultValue: "${GITHUB_REPO}", description: 'Github repo'),
                string(name: 'SERVICE_NAME', defaultValue: 'adservice', description: 'Docker Service Name (e.g., adservice)')
            ])
        ])

        try {
            stage('Checkout') {
                git branch: 'kv-dev',
                    url: "${params.GITHUB_REPO}.git"
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
                    """
                }
            }

        } finally {
            stage('Cleanup') {
                sh """
                    docker rmi ${params.SERVICE_REPO}/${params.SERVICE_NAME}:latest \
                               ${params.ECR_REGISTRY}/${params.SERVICE_REPO}/${params.SERVICE_NAME}:latest || true
                """
                cleanWs(deleteDirs: true)
            }
        }
    }
}
