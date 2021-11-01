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

/* Private subnet */
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
      security_groups  = []
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
      security_groups  = []
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
      security_groups  = []
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
      security_groups  = []
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
resource "aws_instance" "ec2-instance" {
  depends_on                  = [aws_db_instance.rds]
  ami                         = data.aws_ami.testAmi.id
  availability_zone           = var.subnet_az[0]
  disable_api_termination     = false
  subnet_id                   = aws_subnet.public-subnet[0].id
  instance_type               = var.instance_type
  associate_public_ip_address = true
  key_name                    = aws_key_pair.keyPair.key_name
  vpc_security_group_ids      = [aws_security_group.application.id]
  iam_instance_profile        = aws_iam_instance_profile.iam_ec2_roleprofile.id
  user_data                   = data.template_file.config_data.rendered
  root_block_device {
    volume_size           = var.volume_size
    volume_type           = var.volume_type
    delete_on_termination = true
  }
  tags = {
    Name        = "ec2-instance"
    Environment = "development"
    Project     = "DEMO-EC2"
  }
}

resource "aws_eip" "elasticIP" {
  vpc      = true
  instance = aws_instance.ec2-instance.id
}

resource "tls_private_key" "keys" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "keyPair" {
  key_name   = var.key_name
  public_key = var.public_key
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
  owners      = ["self"]
  most_recent = true
}
resource "aws_db_instance" "rds" {
  identifier = "csye6225"
  // identifier = "${local.resource_name_prefix}-${var.identifier}"
  allocated_storage         = var.allocated_storage
  backup_retention_period   = var.backup_retention_period
  backup_window             = var.backup_window
  maintenance_window        = var.maintenance_window
  db_subnet_group_name      = aws_db_subnet_group.awsDbSubnetGrp.name
  engine                    = var.engine
  instance_class            = var.instance_class
  skip_final_snapshot  = true
  // final_snapshot_identifier = false
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
  bucket        = "s3bucket.dev.harshikagupta.me"
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

resource "aws_iam_role" "iam_role" {
  name = "EC2-CSYE6225"
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

resource "aws_iam_policy" "WebAppS3" {
  name        = "WebAppS3"
  description = "IAM Policy"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
                "s3:ListAllMyBuckets", 
              "s3:GetBucketLocation",
              "s3:GetObject",
              "s3:PutObject",
              "s3:DeleteObject"
            ],
      "Effect": "Allow",
      "Resource": ["arn:aws:s3:::${aws_s3_bucket.s3bucket.id}",
                "arn:aws:s3:::${aws_s3_bucket.s3bucket.id}/*"]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.iam_role.name
  policy_arn = aws_iam_policy.WebAppS3.arn
}

resource "aws_iam_instance_profile" "iam_ec2_roleprofile" {
  name = "iam_ec2_roleprofile"
  role = aws_iam_role.iam_role.name
}

