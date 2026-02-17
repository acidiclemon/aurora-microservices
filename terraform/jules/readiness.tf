################################################################################
# Backend Readiness Gate
#
# Ensures all backend microservices and the collector are fully running
# and registered in Service Connect (Cloud Map) BEFORE the frontend is created.
#
# This prevents DNS race conditions where the frontend starts before backends
# have registered their Service Connect DNS entries (e.g. "lookup cartservice
# on 10.0.0.2:53: no such host").
#
# How it works:
#   1. Depends on all aws_ecs_service.microservices and aws_ecs_service.collector
#   2. Runs `aws ecs wait services-stable` which polls every 15s (up to 40
#      attempts = ~10 minutes) until all services reach steady state
#   3. Only then does Terraform proceed to create aws_ecs_service.frontend
################################################################################

resource "terraform_data" "backend_readiness_gate" {
  # Re-run whenever any backend task definition changes
  input = merge(
    { for k, v in aws_ecs_service.microservices : k => v.task_definition },
    { collector = aws_ecs_service.collector.task_definition }
  )

  provisioner "local-exec" {
    command = <<-EOT
      echo "=== Backend Readiness Gate ==="
      echo "Waiting for all backend services to reach steady state..."
      echo "Cluster: ${module.ecs.cluster_name}"

      # Build the list of service names
      SERVICES="${join(" ", [for k, v in aws_ecs_service.microservices : v.name])} ${aws_ecs_service.collector.name}"
      echo "Services: $SERVICES"

      # aws ecs wait services-stable polls every 15s, max 40 attempts (~10 min)
      aws ecs wait services-stable \
        --cluster "${module.ecs.cluster_name}" \
        --services $SERVICES \
        --region "${var.region}"

      EXIT_CODE=$?
      if [ $EXIT_CODE -eq 0 ]; then
        echo "All backend services are stable. Proceeding to create frontend."
      else
        echo "ERROR: Backend services did not stabilize within timeout (exit code: $EXIT_CODE)"
        echo "The frontend will still be created, but may experience DNS resolution errors."
        echo "If that happens, run: aws ecs update-service --cluster ${module.ecs.cluster_name} --service <frontend-service-name> --force-new-deployment"
        # Exit 0 anyway to not block Terraform — the depends_on ordering still helps
        exit 0
      fi
    EOT
  }

  depends_on = [
    aws_ecs_service.microservices,
    aws_ecs_service.collector
  ]
}
