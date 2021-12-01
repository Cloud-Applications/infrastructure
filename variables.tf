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

variable "ports" {
  type        = list(string)
  description = "Security Group Ingress Ports"
}

variable "protocol" {
  type = string
}

variable "ami" {
  type = string
}

variable "protocol_egress" {
  type = string
}

variable "default_port" {
  type = string
}

variable "size" {
  type = string
}
variable "type" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "key_name" {
  type = string
}

variable "allocated_storage" {
  type = number
}

variable "backup_retention_period" {
  type = string
}

variable "backup_window" {
  type = string
}

variable "maintenance_window" {
  type = string
}

variable "engine" {
  type = string
}

variable "instance_class" {
  type = string
}

variable "name" {
  type = string
}

variable "username" {
  type = string
}

variable "password" {
  type = string
}

variable "port" {
  type = string
}

variable "publicly_accessible" {
  type = string
}

variable "storage_encrypted" {
  type = string
}

variable "storage_type" {
  type = string
}

variable "performance_insights_enabled" {
  type = string
}

variable "dbname" {
  type = string
}

variable "volume_size" {
  type = string
}

variable "volume_type" {
  type = string
}

variable "hostname" {
  type = string
}

// variable "public_key" {
//   type = string
// }

variable "private_subnet_cidrs" {
  type = list(string)
}

variable "private_subnet_az" {
  type = list(string)
}

variable "iam_role" {
  type = string
}

variable "domainName" {
  type = string
}

variable "accountId" {
  type = list(any)
}

variable "replica_private_subnet_az" {
  type = list(any)
}

variable "s3bucketName" {
  type = string
}

variable "codeDeployAppName" {
  type = string
}

variable "codeDeployGroupName" {
  type = string
}

variable "mailAddress" {
  type = string
}

variable "dynamo_dbname" {
  type = string
}

variable "replica_private_subnet_cidrs" {
  type = list(any)
}

variable "serverlessBucket" {
  type = string
}

variable "AWS_ACCOUNT_ID" {
  description = "Account Id"
  type        = string
}

variable "CODE_DEPLOY_APPLICATION_NAME" {
  description = "Application Name"
  type        = string
}

variable "aws_iam_user_name" {
  description = " Iam user name"
  type        = string
}

variable "s3bucketNameImage" {
  description = " S3 bucket image name"
  type        = string
}

variable "s3bucketCodeDeployName" {
  type = string
}

variable "replicaAZ" {
  type = string
}

variable "rdsAZ" {
  type = string
}

