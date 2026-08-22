variable "project_name" {
  type    = string
  default = "honeytrace"
}

variable "aws_region" {
  type    = string
  default = "ap-south-1"
}

variable "instance_type" {
	type    = string
	default = "t3.small"
}

variable "root_volume_size" {
	type    = number
	default = 20
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.20.1.0/24"
}
