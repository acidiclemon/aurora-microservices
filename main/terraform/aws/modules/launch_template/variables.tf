variable "name_prefix" {
  type = string
}

variable "image_id" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "iam_instance_profile_arn" {
  type = string
}

variable "security_group_ids" {
  type = list(string)
}

variable "cluster_name" {
  type = string
}
