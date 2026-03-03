#!/usr/bin/env groovy

node {
    properties([
        pipelineTriggers([cron('H 2 * * *')]),
        parameters([
            string(name: 'STAGING_URL', defaultValue: '', description: 'The URL of the staging environment to scan')
        ])
    ])

    docker.image('docker:27.2-dind')
          .inside('--privileged -v /var/run/docker.sock:/var/run/docker.sock -u 0') {

        env.STAGING_URL = params.STAGING_URL ?: ''

        try {
            stage('Validate Parameters') {
                if (!env.STAGING_URL || env.STAGING_URL.trim() == '') {
                    error 'STAGING_URL parameter is empty. Please provide a valid URL to scan.'
                }
            }

            stage('OWASP ZAP Full Scan') {
                sh '''
                    # Download the stable ZAP image
                    docker pull zaproxy/zap-stable
                    
                    # Create a directory for the report
                    mkdir -p zap-reports
                    chmod 777 zap-reports
                    
                    # Run the full scan (Spider + Active Scan)
                    # The -I flag ignores warnings and non-zero exit codes so the pipeline doesn't fail on finding vulnerabilities
                    docker run --name zap-scanner -v $(pwd)/zap-reports:/zap/wrk/:rw -t zaproxy/zap-stable \
                      zap-full-scan.py -t ${STAGING_URL} -r full_scan_report.html -I -a
                '''
            }

        } finally {
            stage('Cleanup') {
                archiveArtifacts artifacts: 'zap-reports/*.html', allowEmptyArchive: true
                
                sh '''
                    # Force remove container in case pipeline was aborted while running
                    docker rm -f zap-scanner || true
                '''
                
                // Fix permission issues created by the docker container running as root
                sh 'chown -R 1000:1000 . || true'
                
                cleanWs(cleanWhenFailure: true, deleteDirs: true, disableDeferredWipeout: true)
            }
        }
    }
}
