# A properly-configured Terraform config, following security best practices.
# Used to demonstrate CloudGuard has a clean, low false-positive rate.

resource "aws_s3_bucket" "data_bucket" {
  bucket = "cloudguard-demo-secure-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data_bucket_pab" {
  bucket                  = aws_s3_bucket.data_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "web_sg" {
  name        = "web-sg-secure"
  description = "Security group for web servers, restricted access"

  ingress {
    description = "SSH from office VPN only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "scoped_policy" {
  name = "scoped-read-only-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = "arn:aws:s3:::cloudguard-demo-secure-bucket/*"
      }
    ]
  })
}

resource "aws_ebs_volume" "encrypted_volume" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
}

resource "aws_db_instance" "private_db" {
  identifier          = "cloudguard-demo-secure-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  publicly_accessible = false
  storage_encrypted   = true
  username            = "admin"
  password            = "changeme123"
  skip_final_snapshot = true
}
