#!/usr/bin/env groovy

node {
    properties([
        pipelineTriggers([cron('H 2 * * *')]),
        parameters([
            string(name: 'zap_scan_target_url', defaultValue: '', description: 'The URL of the target environment to scan'),
            choice(name: 'SCAN_TYPE', choices: ['baseline', 'full'], description: 'Type of ZAP scan to perform'),
            booleanParam(name: 'bypass_auth_with_header', defaultValue: false, description: 'Bypass authentication using X-Automation-Bypass header')
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
                def executeScan = { useAuth ->
                    def scanCmd = ""
                    def reportName = "${env.SCAN_TYPE}_scan_report.html"
                    def replacerArgs = ""
                    
                    if (useAuth) {
                        replacerArgs = "-config replacer.full_list(0).description=auth -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=X-Automation-Bypass -config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=\$BYPASS_SECRET"
                    }
                    
                    if (env.SCAN_TYPE == 'baseline') {
                        def zArgs = useAuth ? " -z \"${replacerArgs}\"" : ""
                        scanCmd = "zap-baseline.py -t ${env.zap_scan_target_url} -r ${reportName} -I${zArgs}"
                    } else if (env.SCAN_TYPE == 'full') {
                        def zArgs = "-config ajaxSpider.browserId=firefox-headless"
                        if (useAuth) {
                            zArgs += " ${replacerArgs}"
                        }
                        scanCmd = "zap-full-scan.py -t ${env.zap_scan_target_url} -r ${reportName} -a -I -j -z \"${zArgs}\""
                    }

                    sh """
                        # Download the stable ZAP image
                        docker pull zaproxy/zap-stable
                        
                        # Create a directory for the report
                        mkdir -p zap-reports
                        
                        # Create a unique named volume and fix permissions using root before dropping to the zap user
                        docker run --rm -u root -v zap_wrk_${env.BUILD_NUMBER}:/zap/wrk zaproxy/zap-stable chown -R 1000:1000 /zap/wrk
                        
                        # Run the scan using the pre-chowned named volume
                        docker run --name zap-scanner --shm-size="2g" -v zap_wrk_${env.BUILD_NUMBER}:/zap/wrk zaproxy/zap-stable \\
                          ${scanCmd}
                    """
                }

                if (params.bypass_auth_with_header) {
                    withCredentials([string(credentialsId: 'X-Automation-Bypass-Secret', variable: 'BYPASS_SECRET')]) {
                        executeScan(true)
                    }
                } else {
                    executeScan(false)
                }
            }

        } finally {
            stage('Cleanup') {
                sh """
                    # Copy the reports out of the container volume before removing it
                    mkdir -p zap-reports
                    docker cp zap-scanner:/zap/wrk/. zap-reports/ || true
                    
                    # Force remove container and volume
                    docker rm -f zap-scanner || true
                    docker volume rm zap_wrk_${env.BUILD_NUMBER} || true
                """
                
                archiveArtifacts artifacts: 'zap-reports/*.html', allowEmptyArchive: true
                
                // Fix permission issues created by the docker container running as root
                sh 'chown -R 1000:1000 . || true'
                
                cleanWs(cleanWhenFailure: true, deleteDirs: true, disableDeferredWipeout: true)
            }
        }
    }
}
