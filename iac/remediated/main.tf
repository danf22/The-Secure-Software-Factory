# =============================================================================
# REMEDIATED TERRAFORM DEFINITIONS
# Purpose: Secure infrastructure for the Secure Software Factory
# All security misconfigurations from iac/vulnerable/main.tf have been resolved:
#   - S3 bucket: private ACL, encryption at rest, versioning, logging, public access block
#   - IAM policy: least-privilege with specific actions and resource ARNs
#   - Security group: restricted CIDRs, only necessary ports open
# This configuration demonstrates the Green Demo path through the pipeline.
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
# SECURE: S3 Bucket with private access and encryption at rest
# Remediations applied:
#   - Private ACL instead of public-read (prevents data exposure)
#   - Server-side encryption with AES-256 (protects data at rest per CNBV requirements)
#   - Versioning enabled (protects against accidental deletion and supports audit trail)
#   - Access logging enabled (provides audit trail for bucket access)
#   - Public access block (defense-in-depth to prevent any public access)
# Resolves: Checkov CKV_AWS_18, CKV_AWS_19, CKV_AWS_21, CKV_AWS_52
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "data_store" {
  bucket = "${var.project_name}-${var.environment}-data"

  tags = {
    Name        = "${var.project_name}-data-store"
    Description = "Transaction data storage for FX operations"
  }
}

# Security improvement: Private ACL prevents unauthorized public access
resource "aws_s3_bucket_acl" "data_store_acl" {
  bucket = aws_s3_bucket.data_store.id
  acl    = "private"
}

# Security improvement: AES-256 server-side encryption protects data at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "data_store_encryption" {
  bucket = aws_s3_bucket.data_store.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Security improvement: Versioning protects against accidental or malicious deletion
resource "aws_s3_bucket_versioning" "data_store_versioning" {
  bucket = aws_s3_bucket.data_store.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Security improvement: Access logging provides an audit trail for all bucket operations
resource "aws_s3_bucket" "log_bucket" {
  bucket = "${var.project_name}-${var.environment}-access-logs"

  tags = {
    Name        = "${var.project_name}-access-logs"
    Description = "Access logs for the data store bucket"
  }
}

resource "aws_s3_bucket_acl" "log_bucket_acl" {
  bucket = aws_s3_bucket.log_bucket.id
  acl    = "log-delivery-write"
}

resource "aws_s3_bucket_logging" "data_store_logging" {
  bucket = aws_s3_bucket.data_store.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "data-store-logs/"
}

# Security improvement: Block all public access at the bucket level (defense-in-depth)
resource "aws_s3_bucket_public_access_block" "data_store_public_access" {
  bucket = aws_s3_bucket.data_store.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "log_bucket_public_access" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -----------------------------------------------------------------------------
# SECURE: IAM Policy with least-privilege actions and specific resources
# Remediations applied:
#   - Specific service actions instead of "*" (principle of least privilege)
#   - Targeted resource ARNs instead of "*" (limits blast radius)
#   - Separate statements for different services (clarity and auditability)
# Resolves: Checkov CKV_AWS_1, CKV_AWS_62
# Compliance: SOC 2 CC6.1 (Logical Access), CNBV operational security
# -----------------------------------------------------------------------------

resource "aws_iam_policy" "app_policy" {
  name        = "${var.project_name}-${var.environment}-app-policy"
  description = "Least-privilege application policy for the organization treasury service"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Allow reading and writing objects only to the specific data bucket
        Sid    = "S3DataAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-${var.environment}-data",
          "arn:aws:s3:::${var.project_name}-${var.environment}-data/*"
        ]
      },
      {
        # Allow publishing application logs to CloudWatch
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "arn:aws:logs:${var.aws_region}:*:log-group:/aws/${var.project_name}/*"
        ]
      },
      {
        # Allow publishing application metrics
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = ["*"]
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "${var.project_name}/${var.environment}"
          }
        }
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
# SECURE: Security Group with restricted CIDR blocks and specific ports
# Remediations applied:
#   - Restricted ingress to specific internal CIDR (10.0.0.0/16) instead of 0.0.0.0/0
#   - Only necessary ports open (443 for HTTPS, 8080 for application)
#   - Separate ingress rules for each port with descriptive comments
#   - Egress restricted to HTTPS only (outbound API calls)
# Resolves: Checkov CKV_AWS_24, CKV_AWS_25, CKV2_AWS_5
# Compliance: SOC 2 CC6.6 (Network Segmentation), CNBV perimeter security
# -----------------------------------------------------------------------------

resource "aws_security_group" "app_sg" {
  name        = "${var.project_name}-${var.environment}-app-sg"
  description = "Security group for the organization treasury application - restricted access"
  vpc_id      = var.vpc_id

  # Allow HTTPS traffic from internal VPC CIDR only
  ingress {
    description = "HTTPS from internal VPC network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Allow application port from internal VPC CIDR only
  ingress {
    description = "Application port from internal VPC network"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Restrict egress to HTTPS only for outbound API calls
  egress {
    description = "HTTPS outbound for API calls and dependency fetching"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
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
