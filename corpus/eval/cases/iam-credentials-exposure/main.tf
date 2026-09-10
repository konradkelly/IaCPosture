resource "aws_iam_policy" "keys" {
  name = "keys"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:CreateAccessKey"]
      Resource = "*"
    }]
  })
}
