resource "aws_kms_key" "good" {
  description         = "rotates"
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "root"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}
