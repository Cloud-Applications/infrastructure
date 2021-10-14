provider "aws" {
  region                  = var.aws_region
  shared_credentials_file = "/Users/harshikag/.aws/creds"
  profile                 = var.aws_profile
}