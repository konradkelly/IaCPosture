resource "aws_lambda_function" "fn" {
  function_name = "fn"
  role          = "arn:aws:iam::123456789012:role/lambda"
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "fn.zip"

  environment {
    variables = {
      STAGE = "dev"
    }
  }

  tracing_config {
    mode = "Active"
  }
}
