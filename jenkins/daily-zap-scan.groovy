pipeline {
    agent {
        docker {
            image 'docker:27.2-dind'
            args '--privileged -v /var/run/docker.sock:/var/run/docker.sock -u 0'
        }
    }
    
    triggers {
        // Run at 2:00 AM every day
        cron('H 2 * * *')
    }

    parameters {
        string(name: 'STAGING_URL', defaultValue: '', description: 'The URL of the staging environment to scan')
    }

    environment {
        STAGING_URL = "${params.STAGING_URL}"
    }

    stages {
        stage('Validate Parameters') {
            steps {
                script {
                    if (!params.STAGING_URL || params.STAGING_URL.trim() == '') {
                        error 'STAGING_URL parameter is empty. Please provide a valid URL to scan.'
                    }
                }
            }
        }
        stage('OWASP ZAP Full Scan') {
            steps {
                sh '''
                # Download the stable ZAP image
                docker pull zaproxy/zap-stable
                
                # Create a directory for the report
                mkdir -p zap-reports
                chmod 777 zap-reports
                
                # Run the full scan (Spider + Active Scan)
                # The -I flag ignores warnings and non-zero exit codes so the pipeline doesn't fail on finding vulnerabilities
                docker run --rm -v $(pwd)/zap-reports:/zap/wrk/:rw -t zaproxy/zap-stable \
                  zap-full-scan.py -t ${STAGING_URL} -r full_scan_report.html -I -a
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'zap-reports/*.html', allowEmptyArchive: true
        }
    }
}
