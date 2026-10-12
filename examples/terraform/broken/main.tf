# BROKEN stack - security issues planted for the IaC scanner to find. Do NOT deploy.

resource "aws_s3_bucket" "evidence" {
  bucket = "acme-evidence-broken"
  # no server-side encryption / public access block / versioning
}

resource "aws_security_group" "app" {
  name = "app"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # SSH open to the world
  }
}

resource "aws_db_instance" "orders" {
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 100
  username            = "admin"
  password            = "hunter2" # inline secret
  storage_encrypted   = false
  publicly_accessible = true
}

resource "aws_iam_policy" "deployer" {
  name = "deployer"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] # full admin
  })
}
