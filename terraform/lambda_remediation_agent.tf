# remediation-agent Lambda (spec §4.1, §4.4 step 5). Reuses the anthropic layer
# declared in lambda_mapping_agent.tf rather than declaring a second copy --
# that layer's description already anticipated this second consumer.

data "archive_file" "remediation_agent_handler" {
  type        = "zip"
  source_file = "${path.module}/../lambda/remediation-agent/handler.py"
  output_path = "${path.module}/../lambda/remediation-agent/handler.zip"
}

resource "aws_cloudwatch_log_group" "remediation_agent" {
  name              = "/aws/lambda/${local.lambda_function_names.remediation_agent}"
  retention_in_days = 14
}

resource "aws_lambda_function" "remediation_agent" {
  function_name = local.lambda_function_names.remediation_agent
  role          = aws_iam_role.remediation_agent.arn

  filename         = data.archive_file.remediation_agent_handler.output_path
  source_code_hash = data.archive_file.remediation_agent_handler.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"

  # Spec §4.1: one trace from the trigger through scan -> map -> remediate,
  # including remediation-agent's synchronous self-check invoke of the
  # scanner. The X-Ray SDK is not needed for that -- Active mode traces the
  # invocation and the boto3 calls it makes.
  tracing_config {
    mode = "Active"
  }

  layers = [aws_lambda_layer_version.anthropic.arn]

  # The handler loops over every mapped finding, and each iteration makes an
  # Anthropic call plus a synchronous terraform-scanner invoke that is itself
  # allowed 300s -- so even the max timeout only fits ~2 findings per run on a
  # cold scanner. Fixing that properly means fanning out one finding per
  # invocation (SQS/Step Functions), not a bigger number here.
  timeout = 900
  # I/O-bound, so no reason to buy the extra CPU terraform-scanner needs.
  memory_size = 512

  environment {
    variables = {
      DYNAMODB_TABLE       = aws_dynamodb_table.findings.name
      ARTIFACTS_BUCKET     = aws_s3_bucket.artifacts.bucket
      ANTHROPIC_SECRET_ARN = aws_secretsmanager_secret.anthropic_api_key.arn
      ANTHROPIC_MODEL      = var.remediation_agent_model
      # The handler needs the scanner's name to invoke it for the self-check.
      # Wired from the resource rather than reconstructed from locals so the
      # dependency is explicit in the graph.
      TERRAFORM_SCANNER_FUNCTION_NAME = aws_lambda_function.terraform_scanner.function_name
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.remediation_agent,
    aws_iam_role_policy.remediation_agent,
  ]
}
