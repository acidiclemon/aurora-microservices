#!/usr/bin/env groovy

properties([
    pipelineTriggers([cron('@midnight')]),
    parameters([
        string(name: 'TARGET_URL', defaultValue: 'http://frontend.aurora.local', description: 'URL to run full ZAP scan against')
    ])
])

node {
    docker.image('docker:27.2-dind')
          .inside('--privileged -v /var/run/docker.sock:/var/run/docker.sock -u 0') {
        
        try {
            stage('Checkout') { checkout scm }

            stage('OWASP ZAP Full Scan') {
                sh 'docker pull owasp/zap2docker-stable:latest'
                // -I means ignore failures (return exit code 0) so the pipeline doesn't crash on high sev issues
                sh """
                    docker run --rm -v \$(pwd):/zap/wrk/:rw \\
                        owasp/zap2docker-stable zap-full-scan.py \\
                        -t \${params.TARGET_URL} -r zap-full-report.html -I
                """
            }
        } finally {
            stage('Archive Report') {
                archiveArtifacts artifacts: 'zap-full-report.html', allowEmptyArchive: true
                
                publishHTML([
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '',
                    reportFiles: 'zap-full-report.html',
                    reportName: 'OWASP ZAP Full Scan Report'
                ])
                
                cleanWs(cleanWhenFailure: true, deleteDirs: true, disableDeferredWipeout: true)
            }
        }
    }
}
