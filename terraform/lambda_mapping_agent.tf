# mapping-agent Lambda (spec §4.1, §4.4 step 4). Layer zip is built locally
# by layers/anthropic/build.sh -- run it before `terraform apply` if the zip
# is missing or stale. Shares the anthropic layer with remediation-agent once
# that Lambda exists.

data "archive_file" "mapping_agent_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/mapping-agent/handler.py"
  output_path = "${path.module}/../lambda/mapping-agent/handler.zip"
}

resource "aws_lambda_layer_version" "anthropic" {
  layer_name          = "${var.project}-${var.environment}-anthropic"
  filename            = "${path.module}/../layers/anthropic/anthropic-layer.zip"
  source_code_hash    = filebase64sha256("${path.module}/../layers/anthropic/anthropic-layer.zip")
  compatible_runtimes = ["python3.12"]
  description         = "anthropic Python SDK + deps under python/"
}

resource "aws_cloudwatch_log_group" "mapping_agent" {
  name              = "/aws/lambda/${local.lambda_function_names.mapping_agent}"
  retention_in_days = 14
}

resource "aws_lambda_function" "mapping_agent" {
  function_name = local.lambda_function_names.mapping_agent
  role          = aws_iam_role.mapping_agent.arn

  filename         = data.archive_file.mapping_agent_handler.output_path
  source_code_hash = data.archive_file.mapping_agent_handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  layers = [aws_lambda_layer_version.anthropic.arn]

  timeout     = 120
  memory_size = 512

  environment {
    variables = {
      DYNAMODB_TABLE       = aws_dynamodb_table.findings.name
      ARTIFACTS_BUCKET     = aws_s3_bucket.artifacts.bucket
      ANTHROPIC_SECRET_ARN = aws_secretsmanager_secret.anthropic_api_key.arn
      ANTHROPIC_MODEL      = var.mapping_agent_model
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.mapping_agent,
    aws_iam_role_policy.mapping_agent,
  ]
}
