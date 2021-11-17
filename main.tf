resource "aws_vpc" "vpc" {
  cidr_block                       = var.vpc_cider
  instance_tenancy                 = local.instance_tenancy
  enable_dns_support               = local.enable_dns_support
  enable_dns_hostnames             = local.enable_dns_hostnames
  enable_classiclink_dns_support   = local.enable_classiclink_dns_support
  assign_generated_ipv6_cidr_block = local.assign_generated_ipv6_cidr_block

  tags = {
    Name = var.vpc_name
  }
}

# Create Internet Gateway and Attach it to VPC
# terraform aws create internet gateway
resource "aws_internet_gateway" "internet-gateway" {

  depends_on = [aws_vpc.vpc]

  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = var.itg_name
  }
}

# Create Public Subnet 1
# terraform aws create subnet
resource "aws_subnet" "public-subnet" {

  depends_on              = [aws_vpc.vpc]
  count                   = length(var.subnet_cidrs)
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.subnet_cidrs[count.index]
  availability_zone       = var.subnet_az[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = var.subnet_names[count.index]
  }
}

/* Private subnets */
resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.vpc.id
  count                   = length(var.private_subnet_az)
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = var.private_subnet_az[count.index]
  map_public_ip_on_launch = false
  tags = {
    Name = "Private Subnet"
  }
}
resource "aws_nat_gateway" "natg" {
  allocation_id = aws_eip.elasticIP.id
  subnet_id     = aws_subnet.private_subnet[0].id

  tags = {
    Name = "gw NAT"
  }

//   # To ensure proper ordering, it is recommended to add an explicit dependency
//   # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.internet-gateway]
}
# Create Route Table and Add Public Route
# terraform aws create route table
resource "aws_route_table" "public-route-table" {

  depends_on = [aws_vpc.vpc, aws_internet_gateway.internet-gateway]

  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet-gateway.id
  }

  tags = {
    Name = var.route_table_name
  }
}

# Associate Public Subnet 1 to "Public Route Table"
# terraform aws associate subnet with route table
resource "aws_route_table_association" "public-subnet-1-route-table-association" {
  count          = length(var.subnet_cidrs)
  subnet_id      = aws_subnet.public-subnet[count.index].id
  route_table_id = aws_route_table.public-route-table.id
}

resource "aws_route_table_association" "private-subnet-route-table-association" {
  count          = length(var.private_subnet_az)
  subnet_id      = aws_subnet.private_subnet[count.index].id
  route_table_id = aws_route_table.public-route-table.id
}

resource "aws_security_group" "application" {
  name        = "application"
  description = "EC2 security group for EC2 instances that will host web application"
  vpc_id      = aws_vpc.vpc.id

  ingress = [
    {
      from_port        = var.ports[2]
      to_port          = var.ports[2]
      protocol         = var.protocol
      description      = "TLS from VPC"
      cidr_blocks      = [aws_vpc.vpc.cidr_block]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.loadBalancerSecurityGrp.id]
      self             = false
    },
    {
      from_port        = var.ports[0]
      to_port          = var.ports[0]
      protocol         = var.protocol
      description      = "SSH from VPC"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.loadBalancerSecurityGrp.id]
      self             = false
    },
    {
      from_port        = var.ports[1]
      to_port          = var.ports[1]
      protocol         = var.protocol
      description      = "HTTP from VPC"
      cidr_blocks      = [aws_vpc.vpc.cidr_block]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.loadBalancerSecurityGrp.id]
      self             = false
    },
    {
      description      = "NODE application"
      from_port        = var.ports[3]
      to_port          = var.ports[3]
      protocol         = var.protocol
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = [aws_security_group.loadBalancerSecurityGrp.id]
      self             = false
    }
  ]
  egress = [
    {
      description      = "HTTP"
      from_port        = var.ports[1]
      to_port          = var.ports[1]
      protocol         = var.protocol
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "HTTPS"
      from_port        = var.ports[2]
      to_port          = var.ports[2]
      protocol         = var.protocol
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "SQL"
      from_port        = var.ports[4]
      to_port          = var.ports[4]
      protocol         = var.protocol
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
  ]
  tags = {
    Name = "application"
  }
}

// Create EC2 instance
// resource "aws_instance" "ec2-instance" {
//   depends_on                  = [aws_db_instance.rds]
//   ami                         = data.aws_ami.testAmi.id
//   availability_zone           = var.subnet_az[0]
//   disable_api_termination     = false
//   subnet_id                   = aws_subnet.public-subnet[0].id
//   instance_type               = var.instance_type
//   associate_public_ip_address = true
//   key_name                    = var.key_name
//   vpc_security_group_ids      = [aws_security_group.application.id]
//   iam_instance_profile        = aws_iam_instance_profile.iam_ec2_roleprofile.name
//   user_data                   = data.template_file.config_data.rendered
//   root_block_device {
//     volume_size           = var.volume_size
//     volume_type           = var.volume_type
//     delete_on_termination = true
//   }
//   tags = {
//     Name        = "webapp"
//   }
// }

resource "aws_eip" "elasticIP" {
  vpc      = true
  depends_on = [aws_internet_gateway.internet-gateway]
}

resource "tls_private_key" "keys" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_db_subnet_group" "awsDbSubnetGrp" {
  name       = "main"
  subnet_ids = [aws_subnet.private_subnet[0].id, aws_subnet.private_subnet[1].id]
}
resource "aws_security_group" "database" {
  depends_on = [aws_vpc.vpc, aws_security_group.application]
  name       = "database"

  description = "RDS Security Group"
  vpc_id      = aws_vpc.vpc.id

  # Only Postgres in
  ingress {
    from_port        = var.ports[4]
    to_port          = var.ports[4]
    protocol         = var.protocol
    cidr_blocks      = [aws_vpc.vpc.cidr_block]
    security_groups  = [aws_security_group.application.id]
    self             = false
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
  }
}
resource "aws_db_parameter_group" "pg" {
  name   = "pg"
  family = "postgres13"
}
data "aws_ami" "testAmi" {
  owners      = var.accountId
  most_recent = true
}
resource "aws_db_instance" "rds" {
  identifier = "csye6225"
  allocated_storage         = var.allocated_storage
  backup_retention_period   = var.backup_retention_period
  backup_window             = var.backup_window
  maintenance_window        = var.maintenance_window
  db_subnet_group_name      = aws_db_subnet_group.awsDbSubnetGrp.name
  engine                    = var.engine
  instance_class            = var.instance_class
  skip_final_snapshot       = true
  multi_az                  = false
  name                      = var.dbname
  parameter_group_name      = aws_db_parameter_group.pg.id
  username                  = var.username
  password                  = var.password
  apply_immediately         = true
  port                   = var.port
  publicly_accessible    = var.publicly_accessible
  storage_encrypted      = var.storage_encrypted
  storage_type           = var.storage_type
  vpc_security_group_ids = [aws_security_group.database.id]
}
resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
}

resource "aws_s3_bucket" "s3bucket" {
  bucket        = var.s3bucketName
  acl           = "private"
  force_destroy = true
  lifecycle_rule {
    id      = "log"
    enabled = true

    prefix = "log/"

    tags = {
      rule      = "log"
      autoclean = "true"
    }
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        // kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm = "AES256"
      }
    }
  }

}

resource "aws_s3_bucket_public_access_block" "block_public_access" {
  bucket = aws_s3_bucket.s3bucket.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

data "template_file" "config_data" {
  template = <<-EOF
		#! /bin/bash
      echo export DB_USERNAME="${var.username}" >> /etc/environment
      echo export DB_NAME="${var.dbname}" >> /etc/environment
      echo export DB_PASSWORD="${var.password}" >> /etc/environment
      echo export DB_HOST="${aws_db_instance.rds.address}" >> /etc/environment
      echo export S3_BUCKET="${aws_s3_bucket.s3bucket.bucket}" >> /etc/environment
      echo export PORT="${var.port}" >> /etc/environment
      EOF
}

data "aws_route53_zone" "selected" {
  name         = var.domainName
  private_zone = false
}

// resource "aws_route53_record" "www" {
//   depends_on = [aws_instance.ec2-instance]
//   zone_id = data.aws_route53_zone.selected.zone_id
//   name    = "${data.aws_route53_zone.selected.name}"
//   type    = "A"
//   ttl     = "60"
//   records = ["${aws_instance.ec2-instance.public_ip}"]
// }

data "aws_iam_role" "iam_role" {
  name = var.iam_role
}

resource "aws_iam_instance_profile" "iam_ec2_roleprofile" {
  name = "iam_ec2_roleprofile"
  role = data.aws_iam_role.iam_role.name
}
data "aws_iam_role" "codeDeployServiceRole" {
  name = "CodeDeployServiceRole"
}
resource "aws_codedeploy_app" "codeDeployApp" {
  name = var.codeDeployAppName
  compute_platform = "Server"
}

resource "aws_codedeploy_deployment_group" "codeDeployGroup" {
  app_name              = aws_codedeploy_app.codeDeployApp.name
  deployment_group_name = var.codeDeployGroupName
  service_role_arn      = data.aws_iam_role.codeDeployServiceRole.arn
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  autoscaling_groups = [aws_autoscaling_group.autoScaleGroup.name]
  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }
  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = "webapp"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  alarm_configuration {
    alarms  = ["deploy-alarm"]
    enabled = true
  }
  load_balancer_info {
    target_group_info {
      name = aws_lb_target_group.LoadBalancerTargetGroup.name
    }
  }
  depends_on = [aws_codedeploy_app.codeDeployApp]
}

resource "aws_launch_configuration" "asg_launch_config" {
    name_prefix = "asg_launch_config"
    image_id = data.aws_ami.testAmi.id
    instance_type = var.instance_type
    key_name = var.key_name
    security_groups = [aws_security_group.application.id]
    associate_public_ip_address = true
    iam_instance_profile        = aws_iam_instance_profile.iam_ec2_roleprofile.name
    user_data = data.template_file.config_data.rendered
    root_block_device {
      volume_size           = var.volume_size
      volume_type           = var.volume_type
      delete_on_termination = true
    }
  depends_on                  = [aws_db_instance.rds]
}

resource "aws_security_group" "loadBalancerSecurityGrp" {
  name        = "loadBalancerSecurityGrp"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    }

   ingress{
    from_port   = 3300
    to_port     = 3300
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    
    }

    ingress{
    description = "Postgres"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    }

  # Allow all outbound traffic.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "loadBalancerSecurityGrp"
  }
}

resource "aws_autoscaling_group" "autoScaleGroup" {
    // availability_zones = [var.subnet_az[0]]
    name = "agents"
    max_size = "5"
    min_size = "3"
    default_cooldown = 60
    desired_capacity = 3
    launch_configuration = aws_launch_configuration.asg_launch_config.name
    vpc_zone_identifier = aws_subnet.public-subnet.*.id
  
  target_group_arns    = [ aws_lb_target_group.LoadBalancerTargetGroup.arn ]
    tag {
        key = "Name"
        value = "webapp"
        propagate_at_launch = true
    }
}

resource "aws_autoscaling_policy" "asg-scale-up" {
    name = "agents-scale-up"
    scaling_adjustment = 1
    adjustment_type = "ChangeInCapacity"
    cooldown = 60
    autoscaling_group_name = aws_autoscaling_group.autoScaleGroup.name
}
// resource "aws_autoscaling_group_tag" "tagForAsg" {
//   autoscaling_group_name = aws_autoscaling_group.id
//   tag {
//     key = "Name"value = "webapp"
//     propagate_at_launch = true
//   }
// }


resource "aws_autoscaling_policy" "asg-scale-down" {
    name = "agents-scale-down"
    scaling_adjustment = -1
    adjustment_type = "ChangeInCapacity"
    cooldown = 60
    autoscaling_group_name = aws_autoscaling_group.autoScaleGroup.name
}

resource "aws_cloudwatch_metric_alarm" "cloudwatchAlarmHigh" {
  alarm_name          = "cloudwatchAlarmHigh"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "5"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.autoScaleGroup.name
  }

  alarm_description = "Scale up if CPU utilization is more then 5%"
  alarm_actions     = [aws_autoscaling_policy.asg-scale-up.arn]
}

resource "aws_cloudwatch_metric_alarm" "cloudwatchAlarmLow" {
  alarm_name          = "cloudwatchAlarmLow"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "3"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.autoScaleGroup.name
  }

  alarm_description = "Scale down if CPU utilization is less then 3%"
  alarm_actions     = [aws_autoscaling_policy.asg-scale-down.arn]
}

resource "aws_lb" "AppLoadBalancer" {
  name               = "AppLoadBalancer"
  internal           = false
  load_balancer_type = "application"
  ip_address_type = "ipv4"
  security_groups    = [aws_security_group.loadBalancerSecurityGrp.id]
  subnets            = aws_subnet.public-subnet.*.id
  tags = {
    Environment = var.aws_profile
    Name = "AppLoadBalancer"
  }
}

resource "aws_lb_target_group" "LoadBalancerTargetGroup" {
  name     = "LoadBalancerTargetGroup"
  port     = 3300
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id

  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    port                = "3300"
    //still not sure about path
    path              = "/healthstatus" 
    interval            = 30
    matcher = "200"
  }
  tags     = {    
    name = "alb-target-group"    
  }
}

resource "aws_lb_listener" "alb_listener" {
  load_balancer_arn = aws_lb.AppLoadBalancer.arn
  port              = "80"
  protocol          = "HTTP"
  // certificate_arn   = data.aws_acm_certificate.aws_ssl_certificate.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.LoadBalancerTargetGroup.arn
  }
}

 # AWS Route53 Alias Record for ALB
 resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = data.aws_route53_zone.selected.name
  type    = "A"
  
  alias {
    name = aws_lb.AppLoadBalancer.dns_name
    zone_id = aws_lb.AppLoadBalancer.zone_id
    evaluate_target_health = true
  }
}
