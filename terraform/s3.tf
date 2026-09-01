# Single bucket, two prefixes:
#   scans/  - raw Terraform snapshots per scan run + scanner output artifacts (transient)
#   corpus/ - versioned CIS/OWASP control text (long-lived, relies on bucket versioning)
resource "aws_s3_bucket" "artifacts" {
  bucket = "${var.project}-${var.environment}-artifacts-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# scans/ are per-run artifacts, not meant to be retained indefinitely
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-scan-snapshots"
    status = "Enabled"

    filter {
      prefix = "scans/"
    }

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}
