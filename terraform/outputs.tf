output "artifacts_bucket_name" {
  value = aws_s3_bucket.artifacts.bucket
}

output "findings_table_name" {
  value = aws_dynamodb_table.findings.name
}

output "findings_table_arn" {
  value = aws_dynamodb_table.findings.arn
}

output "anthropic_api_key_secret_arn" {
  value = aws_secretsmanager_secret.anthropic_api_key.arn
}

output "lambda_role_arns" {
  value = {
    terraform_scanner = aws_iam_role.terraform_scanner.arn
    mapping_agent     = aws_iam_role.mapping_agent.arn
    remediation_agent = aws_iam_role.remediation_agent.arn
    review_api        = aws_iam_role.review_api.arn
  }
}

output "terraform_scanner_function_name" {
  value = aws_lambda_function.terraform_scanner.function_name
}

output "terraform_scanner_function_arn" {
  value = aws_lambda_function.terraform_scanner.arn
}
