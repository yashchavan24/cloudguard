# Intentionally vulnerable Terraform config for demoing CloudGuard.
# DO NOT deploy this as-is — it exists purely to trigger every rule.

resource "aws_s3_bucket" "data_bucket" {
  bucket = "cloudguard-demo-public-bucket"
  acl    = "public-read"
  # no server_side_encryption_configuration -> triggers CG002
  # no versioning block -> triggers CG003
}

resource "aws_s3_bucket_public_access_block" "data_bucket_pab" {
  bucket                  = aws_s3_bucket.data_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "Security group for web servers"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow everything"
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "overly_broad" {
  name = "overly-broad-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_ebs_volume" "unencrypted_volume" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

resource "aws_db_instance" "public_db" {
  identifier             = "cloudguard-demo-db"
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  publicly_accessible    = true
  storage_encrypted      = false
  username               = "admin"
  password               = "changeme123"
  skip_final_snapshot    = true
}

resource "aws_lambda_function" "risky_function" {
  function_name = "process-orders"
  handler       = "index.handler"
  runtime       = "python3.12"
  role          = "arn:aws:iam::123456789012:role/lambda-admin-role"
  filename      = "function.zip"
}
