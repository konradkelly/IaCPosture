resource "aws_iam_policy" "escalate" {
  name = "escalate"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
      Resource = "*"
    }]
  })
}
