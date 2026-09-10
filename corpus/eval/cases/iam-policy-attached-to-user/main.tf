resource "aws_iam_user" "alice" {
  name = "alice"
}

resource "aws_iam_user_policy" "alice" {
  name = "alice-s3"
  user = aws_iam_user.alice.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::example-bucket/*"]
    }]
  })
}
