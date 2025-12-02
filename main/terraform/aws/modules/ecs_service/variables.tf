variable "name" {
  type = string
}

variable "cluster_id" {
  type = string
}

variable "task_definition_arn" {
  type = string
}

variable "desired_count" {
  type = number
}

variable "subnet_ids" {
  type = list(string)
}

variable "security_group_ids" {
  type = list(string)
}

variable "capacity_provider_name" {
  type = string
}

variable "target_group_arn" {
  type = string
  default = ""
}

variable "container_name" {
  type = string
  default = ""
}

variable "container_port" {
  type = number
  default = 0
}

variable "service_registry_arn" {
  type = string
  default = ""
}
