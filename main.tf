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
      cidr_blocks      = []
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
      cidr_blocks      = []
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
      cidr_blocks      = []
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

resource "aws_eip" "elasticIP" {
  vpc        = true
  depends_on = [aws_internet_gateway.internet-gateway]
}

resource "tls_private_key" "keys" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_db_subnet_group" "awsDbSubnetGrp" {
  name       = "main"
  subnet_ids = [aws_subnet.private_subnet[0].id, aws_subnet.private_subnet[1].id, aws_subnet.private_subnet[2].id]
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
  parameter {
    name  = "rds.force_ssl"
    value = 1
  }
  // parameter {
  //   name  = "performance_schema"
  //   value = "1"
  //   apply_method = "pending-reboot"
  // }
}
data "aws_ami" "testAmi" {
  owners      = var.accountId
  most_recent = true
}
resource "aws_db_instance" "rds" {
  identifier                 = "csye6225"
  allocated_storage          = var.allocated_storage
  backup_retention_period    = var.backup_retention_period
  backup_window              = var.backup_window
  auto_minor_version_upgrade = true
  engine_version             = "13.4"
  maintenance_window         = var.maintenance_window
  db_subnet_group_name       = aws_db_subnet_group.awsDbSubnetGrp.name
  engine                     = var.engine
  instance_class             = var.instance_class
  skip_final_snapshot        = true
  multi_az                   = false
  name                       = var.dbname
  parameter_group_name       = aws_db_parameter_group.pg.id
  username                   = var.username
  password                   = var.password
  apply_immediately          = true
  port                       = var.port
  publicly_accessible        = var.publicly_accessible
  storage_encrypted          = var.storage_encrypted
  storage_type               = var.storage_type
  vpc_security_group_ids     = [aws_security_group.database.id]
  kms_key_id                 = aws_kms_key.keyForRds.arn
  availability_zone          = var.rdsAZ
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

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "template_file" "config_data" {
  template = <<-EOF
		#! /bin/bash
      echo export DB_USERNAME="${var.username}" >> /etc/environment
      echo export DOMAIN_NAME="${var.domainName}" >> /etc/environment
      echo export TOPIC_ARN="${aws_sns_topic.snsTopic.arn}" >> /etc/environment
      echo export DB_NAME="${var.dbname}" >> /etc/environment
      echo export DB_PASSWORD="${var.password}" >> /etc/environment
      echo export DB_HOST="${aws_db_instance.rds.address}" >> /etc/environment
      echo export S3_BUCKET="${aws_s3_bucket.s3bucket.bucket}" >> /etc/environment
      echo export Replica_DB_HOST="${aws_db_instance.rds_replica.address}" >> /etc/environment
      echo export PORT="${var.port}" >> /etc/environment
      EOF
}

data "aws_route53_zone" "selected" {
  name         = var.domainName
  private_zone = false
}

// data "aws_iam_role" "iam_role" {
//   name = var.iam_role
// }

// resource "aws_iam_instance_profile" "iam_ec2_roleprofile" {
//   name = "iam_ec2_roleprofile"
//   role = aws_iam_role.CodeDeployEC2ServiceRole.name
// }
// data "aws_iam_role" "codeDeployServiceRole" {
//   name = "CodeDeployServiceRole"
// }
resource "aws_codedeploy_app" "codeDeployApp" {
  name             = var.codeDeployAppName
  compute_platform = "Server"
}

resource "aws_codedeploy_deployment_group" "codeDeployGroup" {
  app_name               = aws_codedeploy_app.codeDeployApp.name
  deployment_group_name  = var.codeDeployGroupName
  service_role_arn       = aws_iam_role.CodeDeployServiceRole.arn
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  autoscaling_groups     = [aws_autoscaling_group.autoScaleGroup.name]
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

resource "aws_kms_key" "keyForEC2" {
  description             = "ec2 key"
  deletion_window_in_days = 10
  policy                  = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::${var.accountId[1]}:root"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {"AWS": [
        "arn:aws:iam::${var.accountId[1]}:user/${var.aws_iam_user_name}",
        "arn:aws:iam::${var.accountId[1]}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
      ]},
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {"AWS": [
        "arn:aws:iam::${var.accountId[1]}:user/${var.aws_iam_user_name}",
        "arn:aws:iam::${var.accountId[1]}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
        "arn:aws:iam::${var.accountId[1]}:root"
      ]},
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {"AWS": [
        "arn:aws:iam::${var.accountId[1]}:user/${var.aws_iam_user_name}",
        "arn:aws:iam::${var.accountId[1]}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
        "arn:aws:iam::${var.accountId[1]}:root"
      ]},
      "Action": [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Resource": "*",
      "Condition": {"Bool": {"kms:GrantIsForAWSResource": "true"}}
    }
  ]
}
EOF
}

resource "aws_kms_key" "keyForRds" {
  description             = "rds key"
  deletion_window_in_days = 10
}

resource "aws_launch_template" "asg_launch_template" {
  depends_on = [aws_db_instance.rds]
  name       = "asg_launch_template"
  iam_instance_profile {
    name = aws_iam_instance_profile.iam_ec2_profileRole.name
  }
  key_name               = var.key_name
  image_id               = data.aws_ami.testAmi.id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.application.id]
  user_data              = base64encode(data.template_file.config_data.rendered)
  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.volume_size
      volume_type           = var.volume_type
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.keyForEC2.arn
    }
  }
}
// resource "aws_launch_configuration" "asg_launch_config" {
//   name_prefix                 = "asg_launch_config"
//   image_id                    = data.aws_ami.testAmi.id
//   instance_type               = var.instance_type
//   key_name                    = var.key_name
//   security_groups             = [aws_security_group.application.id]
//   associate_public_ip_address = true
//   // root_block_device = aws_ebs_volume.ebsVol.id
//   // key_name                    = aws_kms_key.keyForEC2.id
//   iam_instance_profile        = aws_iam_instance_profile.iam_ec2_profileRole.name
//   // root_block_device = aws_ebs_volume.ebsVol.id
//   user_data                   = <<-EOF
// 		#! /bin/bash
//       echo export DB_USERNAME="${var.username}" >> /etc/environment
//       echo export DOMAIN_NAME="${var.domainName}" >> /etc/environment
//       echo export TOPIC_ARN="${aws_sns_topic.snsTopic.arn}" >> /etc/environment
//       echo export DB_NAME="${var.dbname}" >> /etc/environment
//       echo export DB_PASSWORD="${var.password}" >> /etc/environment
//       echo export DB_HOST="${aws_db_instance.rds.address}" >> /etc/environment
//       echo export Replica_DB_HOST="${aws_db_instance.rds_replica.address}" >> /etc/environment
//       echo export S3_BUCKET="${aws_s3_bucket.s3bucket.bucket}" >> /etc/environment
//       echo export PORT="${var.port}" >> /etc/environment
//       EOF
//   root_block_device {
//     volume_size           = var.volume_size
//     volume_type           = var.volume_type
//     delete_on_termination = true
//     encrypted = true
//     // kms_key_id = aws_kms_key.keyForEC2.id
//   }
//   depends_on = [aws_db_instance.rds]
// }

resource "aws_security_group" "loadBalancerSecurityGrp" {
  name   = "loadBalancerSecurityGrp"
  vpc_id = aws_vpc.vpc.id
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

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3300
    to_port     = 3300
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  ingress {
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
  name             = "agents"
  max_size         = "5"
  min_size         = "3"
  default_cooldown = 60
  desired_capacity = 3
  // launch_configuration = aws_launch_configuration.asg_launch_config.name
  vpc_zone_identifier = aws_subnet.public-subnet.*.id
  launch_template {
    id      = aws_launch_template.asg_launch_template.id
    version = aws_launch_template.asg_launch_template.latest_version
  }
  target_group_arns = [aws_lb_target_group.LoadBalancerTargetGroup.arn]
  tag {
    key                 = "Name"
    value               = "webapp"
    propagate_at_launch = true
  }
}

resource "aws_autoscaling_policy" "asg-scale-up" {
  name                   = "agents-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.autoScaleGroup.name
}

resource "aws_autoscaling_policy" "asg-scale-down" {
  name                   = "agents-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
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
  ip_address_type    = "ipv4"
  security_groups    = [aws_security_group.loadBalancerSecurityGrp.id]
  subnets            = [aws_subnet.public-subnet[0].id, aws_subnet.public-subnet[1].id]
  tags = {
    Environment = var.aws_profile
    Name        = "AppLoadBalancer"
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
    path     = "/healthstatus"
    interval = 30
    matcher  = "200"
  }
  tags = {
    name = "alb-target-group"
  }
}

// resource "aws_lb_listener" "alb_listener" {
//   load_balancer_arn = aws_lb.AppLoadBalancer.arn
//   port              = "80"
//   protocol          = "HTTP"
//   default_action {
//     type             = "forward"
//     target_group_arn = aws_lb_target_group.LoadBalancerTargetGroup.arn
//   }
// }

# AWS Route53 Alias Record for ALB
resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = data.aws_route53_zone.selected.name
  type    = "A"

  alias {
    name                   = aws_lb.AppLoadBalancer.dns_name
    zone_id                = aws_lb.AppLoadBalancer.zone_id
    evaluate_target_health = true
  }
}

resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambdaFn.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.snsTopic.arn
}

resource "aws_sns_topic" "snsTopic" {
  name = "snsTopic"
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.snsTopic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.lambdaFn.arn
}

resource "aws_sns_topic_policy" "snsPolicy" {
  arn = aws_sns_topic.snsTopic.arn

  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        var.accountId[1],
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.snsTopic.arn,
    ]

    sid = "__default_statement_ID"
  }
}

# IAM policy for SNS
resource "aws_iam_policy" "sns_iam_policy" {
  name   = "sns_iam_policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "SNS:Publish"
      ],
      "Resource": "${aws_sns_topic.snsTopic.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "lambda_function_ec2_policy" {
  name        = "Update-lambda-function"
  description = "Policy to update lambda function"
  policy      = <<EOF
{
 "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": "lambda:UpdateFunctionCode",
            "Resource": "arn:aws:lambda:${var.aws_region}:${var.accountId[1]}:function:lambda_called_from_sns"
        }
    ] 
}
EOF
}

resource "aws_iam_role_policy_attachment" "ec2_sns_policy_attach" {
  policy_arn = aws_iam_policy.sns_iam_policy.arn
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
}

resource "aws_lambda_function" "lambdaFn" {
  filename      = "lambdaFn.zip"
  function_name = "lambda_called_from_sns"
  role          = aws_iam_role.lambdaRole.arn
  handler       = "index.handler"
  runtime       = "nodejs12.x"
}

resource "aws_iam_role" "lambdaRole" {
  name = "iam_for_lambda_with_sns"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
}

# Lambda Policy
resource "aws_iam_policy" "lambda_policy" {
  name        = "lambda_policy"
  description = "Policy for Dynamo DB and SES"
  policy      = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
      {
           "Effect": "Allow",
           "Action": "logs:CreateLogGroup",
           "Resource": "arn:aws:logs:${var.aws_region}:${var.accountId[1]}:*"
       },
        {
           "Effect": "Allow",
           "Action": [
               "logs:CreateLogStream",
               "logs:PutLogEvents"
           ],
           "Resource": [
              "arn:aws:logs:${var.aws_region}:${var.accountId[1]}:log-group:/aws/lambda/${aws_lambda_function.lambdaFn.function_name}:*"
          ]
       },
       {
         "Sid": "LambdaDynamoDBAccess",
         "Effect": "Allow",
         "Action": [
             "dynamodb:GetItem",
             "dynamodb:PutItem",
             "dynamodb:UpdateItem",
             "dynamodb:Scan",
             "dynamodb:DeleteItem"
         ],
         "Resource": "arn:aws:dynamodb:${var.aws_region}:${var.accountId[1]}:table/${var.dynamo_dbname}"
       },
       {
         "Sid": "LambdaSESAccess",
         "Effect": "Allow",
         "Action": [
             "ses:VerifyEmailAddress",
             "ses:SendEmail",
             "ses:SendRawEmail"
         ],
         "Resource": "*",
          "Condition":{
            "StringEquals":{
              "ses:FromAddress":"${var.mailAddress}@${var.domainName}"
            }
          }
       }
   ]
}
 EOF
}

# Attach the policy for Lambda IAM role
resource "aws_iam_role_policy_attachment" "lambdaRolePolicyAttach" {
  role       = aws_iam_role.lambdaRole.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

resource "aws_db_instance" "rds_replica" {
  depends_on = [aws_db_instance.rds]
  identifier = "replica-csye6225"
  engine = var.engine
  auto_minor_version_upgrade = true
  engine_version = "13.4"
  instance_class = "db.t3.micro"
  name = "read_replica_indentifier"
  // multi_az = true
  skip_final_snapshot       = true
  publicly_accessible    = var.publicly_accessible
  replicate_source_db = aws_db_instance.rds.id
  // db_subnet_group_name       = aws_db_subnet_group.replica_awsDbSubnetGrp.name
  availability_zone = var.replicaAZ
}

resource "aws_dynamodb_table" "dynamo_db" {
  name           = var.dynamo_dbname
  hash_key       = "token"
  read_capacity  = 20
  write_capacity = 20
  billing_mode   = "PROVISIONED"

  attribute {
    name = "token"
    type = "S"
  }
  // attribute {
  //   name = "username"
  //   type = "S"
  // }
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name = var.dynamo_dbname
  }
}

resource "aws_iam_policy" "dynamoDbPolicy" {
  name        = "dynamoDbPolicy"
  description = "Dynamo db policy"
  policy      = <<-EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [      
              "dynamodb:List*",
              "dynamodb:DescribeReservedCapacity*",
              "dynamodb:DescribeLimits",
              "dynamodb:DescribeTimeToLive"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:BatchGet*",
                "dynamodb:DescribeStream",
                "dynamodb:DescribeTable",
                "dynamodb:Get*",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchWrite*",
                "dynamodb:CreateTable",
                "dynamodb:Delete*",
                "dynamodb:Update*",
                "dynamodb:PutItem"
            ],
            "Resource": "arn:aws:dynamodb:${var.aws_region}:${var.accountId[1]}:table/${var.dynamo_dbname}"
        }
    ]
    }
    EOF
}

resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name = "/aws/lambda/${aws_lambda_function.lambdaFn.function_name}"
}

resource "aws_iam_role_policy_attachment" "attachDynamoDbPolicyToRole" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.dynamoDbPolicy.arn
}

resource "aws_s3_bucket" "serverlessBucket" {
  bucket        = var.serverlessBucket
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

resource "aws_s3_bucket_public_access_block" "block_public_access_serverless" {
  bucket = aws_s3_bucket.serverlessBucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name = "CodeDeploy-EC2-S3"
  // user = aws_iam_user.lb.name
  description = "AMI Policy"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:Get*",
        "s3:List*",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::${var.s3bucketCodeDeployName}/*",
        "arn:aws:s3:::${var.serverlessBucket}/*",
        "arn:aws:s3:::${var.s3bucketNameImage}/*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_policy" "GH-Upload-To-S3" {
  name = "GH-Upload-To-S3"
  // user = aws_iam_user.lb.name
  description = "AMI Policy"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:Get*",
                  "s3:List*",
                  "s3:PutObject",
                  "s3:DeleteObject",
                  "s3:DeleteObjectVersion"
            ],
            "Resource": ["arn:aws:s3:::${var.s3bucketCodeDeployName}", "arn:aws:s3:::${var.s3bucketCodeDeployName}/*",
            "arn:aws:s3:::${var.serverlessBucket}", "arn:aws:s3:::${var.serverlessBucket}/*"]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "GH-Code-Deploy" {
  name = "GH-Code-Deploy"
  // user = aws_iam_user.lb.name
  description = "AMI Policy"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.aws_region}:${var.AWS_ACCOUNT_ID}:application:${var.CODE_DEPLOY_APPLICATION_NAME}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.aws_region}:${var.AWS_ACCOUNT_ID}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.aws_region}:${var.AWS_ACCOUNT_ID}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.aws_region}:${var.AWS_ACCOUNT_ID}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_policy" "gh-ec2-ami" {
  name = "gh-ec2-ami"
  // user = aws_iam_user.lb.name
  description = "AMI Policy"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

# IAM Role for CodeDeploy
resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

data "aws_iam_user" "appUser" {
  user_name = var.aws_iam_user_name
}

resource "aws_iam_role_policy_attachment" "CodeDeploy-EC2-S3" {
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
  policy_arn = aws_iam_policy.CodeDeploy-EC2-S3.arn
}

# Attach the policy for CodeDeploy role for webapp
resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = aws_iam_role.CodeDeployServiceRole.name
}

# Attach the Cloud eatch agent policy for CodeDeployEC2ServiceRole role for webapp
resource "aws_iam_role_policy_attachment" "AWSCodeDeployEC2SerciceRole" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.CodeDeployEC2ServiceRole.name
}

resource "aws_iam_user_policy_attachment" "ec2_ami_policy_attach" {
  user       = data.aws_iam_user.appUser.user_name
  policy_arn = aws_iam_policy.gh-ec2-ami.arn
}

resource "aws_iam_user_policy_attachment" "code_upload_policy_attach" {
  user       = data.aws_iam_user.appUser.user_name
  policy_arn = aws_iam_policy.GH-Upload-To-S3.arn
}

resource "aws_iam_user_policy_attachment" "code_deploy_policy_attach" {
  user       = data.aws_iam_user.appUser.user_name
  policy_arn = aws_iam_policy.GH-Code-Deploy.arn
}

resource "aws_iam_user_policy_attachment" "lambda_dunction_ec2_policy_attach" {
  user       = data.aws_iam_user.appUser.user_name
  policy_arn = aws_iam_policy.lambda_function_ec2_policy.arn
}

resource "aws_iam_instance_profile" "iam_ec2_profileRole" {
  name = "iam_ec2_profileRole"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}

data "aws_acm_certificate" "certificate" {
  domain   = var.domainName
  statuses = ["ISSUED"]
}

resource "aws_lb_listener" "alb_listener_ssl" {
  load_balancer_arn = aws_lb.AppLoadBalancer.arn
  port              = "443"
  protocol          = "HTTPS"
  // ssl_policy        = "SSL_Policy"
  certificate_arn = data.aws_acm_certificate.certificate.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.LoadBalancerTargetGroup.arn
  }
}