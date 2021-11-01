locals {
  enable_dns_support               = true
  enable_dns_hostnames             = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false
  instance_tenancy                 = "default"
  // resource_name_prefix = "${var.namespace}-${var.resource_tag_name}"
}