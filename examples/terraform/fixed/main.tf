variable "db_password" {
  description = "Database password, supplied by the deployer (Secrets Manager in production)"
  type        = string
  sensitive   = true
}

# FIXED stack - same resources, remediated. This is the PR you would open.

resource "aws_s3_bucket" "evidence" {
  bucket = "acme-evidence-broken"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_security_group" "app" {
  name = "app"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "orders" {
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 100
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = false
}

resource "aws_iam_policy" "deployer" {
  name = "deployer"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["s3:GetObject", "s3:PutObject"],
      Resource = ["arn:aws:s3:::acme-evidence-broken/*"]
    }]
  })
}
