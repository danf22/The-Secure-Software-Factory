# =============================================================================
# INTENTIONALLY INSECURE TERRAFORM DEFINITIONS
# Purpose: Security scanning demonstration for the Secure Software Factory
# These resources contain deliberate misconfigurations for Checkov/Conftest detection
# DO NOT deploy this configuration to any environment
# =============================================================================

# -----------------------------------------------------------------------------
# Provider Configuration
# -----------------------------------------------------------------------------

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "secure-factory"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "vpc_id" {
  description = "VPC ID for security group placement"
  type        = string
  default     = "vpc-0example123456789"
}

# -----------------------------------------------------------------------------
# INSECURE: S3 Bucket with public read access and NO encryption
# Violations:
#   - Public ACL exposes data to the internet
#   - No server-side encryption at rest (violates CNBV data protection requirements)
#   - No versioning enabled
#   - No access logging configured
# Detected by: Checkov CKV_AWS_18, CKV_AWS_19, CKV_AWS_21, CKV_AWS_52
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "data_store" {
  bucket = "${var.project_name}-${var.environment}-data"
  acl    = "public-read"

  tags = {
    Name        = "${var.project_name}-data-store"
    Description = "Transaction data storage for FX operations"
  }
}

# No aws_s3_bucket_server_side_encryption_configuration resource defined
# No aws_s3_bucket_versioning resource defined
# No aws_s3_bucket_logging resource defined
# No aws_s3_bucket_public_access_block resource defined

# -----------------------------------------------------------------------------
# INSECURE: IAM Policy with wildcard actions and resources
# Violations:
#   - "Action": "*" grants unrestricted access to all AWS services
#   - "Resource": "*" applies to all resources in the account
#   - Violates principle of least privilege (SOC 2 CC6.1, CNBV operational security)
# Detected by: Checkov CKV_AWS_1, CKV_AWS_62
# -----------------------------------------------------------------------------

resource "aws_iam_policy" "app_policy" {
  name        = "${var.project_name}-${var.environment}-app-policy"
  description = "Application policy for the organization treasury service"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullAccess"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-app-policy"
  }
}

resource "aws_iam_role" "app_role" {
  name = "${var.project_name}-${var.environment}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-app-role"
  }
}

resource "aws_iam_role_policy_attachment" "app_policy_attachment" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.app_policy.arn
}

# -----------------------------------------------------------------------------
# INSECURE: Security Group open to the entire internet
# Violations:
#   - Ingress from 0.0.0.0/0 on all ports allows unrestricted inbound traffic
#   - No restriction on protocols (all traffic allowed)
#   - Violates network segmentation requirements (SOC 2 CC6.6, CNBV perimeter security)
# Detected by: Checkov CKV_AWS_24, CKV_AWS_25, CKV2_AWS_5
# -----------------------------------------------------------------------------

resource "aws_security_group" "app_sg" {
  name        = "${var.project_name}-${var.environment}-app-sg"
  description = "Security group for the organization treasury application"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow all inbound traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-app-security-group"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "s3_bucket_name" {
  description = "Name of the data storage bucket"
  value       = aws_s3_bucket.data_store.id
}

output "iam_policy_arn" {
  description = "ARN of the application IAM policy"
  value       = aws_iam_policy.app_policy.arn
}

output "security_group_id" {
  description = "ID of the application security group"
  value       = aws_security_group.app_sg.id
}
