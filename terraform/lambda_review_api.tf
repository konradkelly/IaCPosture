# review-api Lambda (spec §4.1, §4.4 step 6). No layers -- boto3 is already in
# the Lambda Python runtime and this function calls nothing else.

data "archive_file" "review_api_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/review-api/handler.py"
  output_path = "${path.module}/../lambda/review-api/handler.zip"
}

resource "aws_cloudwatch_log_group" "review_api" {
  name              = "/aws/lambda/${local.lambda_function_names.review_api}"
  retention_in_days = 14
}

resource "aws_lambda_function" "review_api" {
  function_name = local.lambda_function_names.review_api
  role          = aws_iam_role.review_api.arn

  filename         = data.archive_file.review_api_handler.output_path
  source_code_hash = data.archive_file.review_api_handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  # Interactive request path -- a dashboard user is waiting on every call, and
  # the work is a couple of DynamoDB round-trips. Unlike the agent Lambdas this
  # wants low latency, not a long ceiling.
  timeout     = 10
  memory_size = 256

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.findings.name
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.review_api,
    aws_iam_role_policy.review_api,
  ]
}
