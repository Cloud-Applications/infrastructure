variable "aws_profile" {
  description = "Aws profile"
  type        = string
}

variable "aws_region" {
  description = "Aws region"
  type        = string
}

variable "vpc_cider" {
  description = "VPC Cider Block"
  type        = string
}

variable "vpc_name" {
  description = "VPC Cider Block"
  type        = string
}
variable "subnet_cidrs" {
  type        = list(string)
  description = "Public Subnet Cider Blocks"
}

variable "subnet_az" {
  type        = list(string)
  description = "Public Subnet Availability Zones"
}

variable "subnet_names" {
  type        = list(string)
  description = "Public Subnet Name Tags"
}

variable "itg_name" {
  type        = string
  description = "Internet Gateway Name Tags"
}

variable "route_table_name" {
  type        = string
  description = "Route Table Name Tags"
}


