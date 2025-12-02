output "iam_instance_profile_arn" {
  value = aws_iam_instance_profile.ecs_instance_profile.arn
}

output "role_arn" {
  value = aws_iam_role.ecs_instance_role.arn
}
