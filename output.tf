output "vpc_id" {
  value = aws_vpc.vpc.id
}

output "aws_internet_gateway_id" {
  value = aws_internet_gateway.internet-gateway.id
}

output "aws_subnet_id" {
  value = { for k, v in aws_subnet.public-subnet : k => v.id }
}

output "public-route-table_id" {
  value = aws_route_table.public-route-table.id
}

output "aws_security_group_id" {
  value = aws_security_group.application.id
}

output "rds_hostname" {
  value       = aws_db_instance.rds.address
  description = "rds hostname"
}
output "rds_port" {
  description = "RDS instance port"
  value       = aws_db_instance.rds.port
  sensitive   = true
}
output "rds_username" {
  description = "RDS instance root username"
  value       = aws_db_instance.rds.username
  sensitive   = true
}
