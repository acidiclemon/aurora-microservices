variable "name" {
  type = string
}

variable "port" {
  type = number
}

variable "protocol" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "health_check_path" {
  type = string
  default = "/"
}
