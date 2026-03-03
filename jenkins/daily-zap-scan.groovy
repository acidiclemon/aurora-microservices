#!/usr/bin/env groovy

node {
    properties([
        pipelineTriggers([cron('H 2 * * *')]),
        parameters([
            string(name: 'zap_scan_target_url', defaultValue: '', description: 'The URL of the target environment to scan'),
            choice(name: 'SCAN_TYPE', choices: ['baseline', 'full'], description: 'Type of ZAP scan to perform')
        ])
    ])

    docker.image('docker:27.2-dind')
          .inside('--privileged -v /var/run/docker.sock:/var/run/docker.sock -u 0') {

        env.zap_scan_target_url = params.zap_scan_target_url ?: ''
        env.SCAN_TYPE = params.SCAN_TYPE ?: 'baseline'

        try {
            stage('Validate Parameters') {
                if (!env.zap_scan_target_url || env.zap_scan_target_url.trim() == '') {
                    error 'zap_scan_target_url parameter is empty. Please provide a valid URL to scan.'
                }
            }

            stage("OWASP ZAP ${env.SCAN_TYPE.capitalize()} Scan") {
                def scanCmd = ""
                def reportName = "${env.SCAN_TYPE}_scan_report.html"
                
                if (env.SCAN_TYPE == 'baseline') {
                    // -m 2 limits the spider to 2 minutes max
                    scanCmd = "zap-baseline.py -t ${env.zap_scan_target_url} -r ${reportName} -m 2 -I"
                } else if (env.SCAN_TYPE == 'full') {
                    scanCmd = "zap-full-scan.py -t ${env.zap_scan_target_url} -r ${reportName} -a -I"
                }

                sh """
                    # Download the stable ZAP image
                    docker pull zaproxy/zap-stable
                    
                    # Create a directory for the report
                    mkdir -p zap-reports
                    chown -R 1000:1000 zap-reports
                    chmod -R 777 zap-reports
                    
                    # Run the scan
                    docker run --name zap-scanner -v \$(pwd)/zap-reports:/zap/wrk/:rw zaproxy/zap-stable \\
                      \${scanCmd}
                """
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
