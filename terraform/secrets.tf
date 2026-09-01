# GitHub App secrets deferred to v3 (CI integration) — not needed for v1's
# manual-trigger flow, so not created here.
resource "aws_secretsmanager_secret" "anthropic_api_key" {
  name        = "${var.project}/${var.environment}/anthropic-api-key"
  description = "Anthropic API key used by mapping-agent and remediation-agent Lambdas"
}

# Placeholder value — set the real key out-of-band (console or `aws secretsmanager
# put-secret-value`) after apply. lifecycle.ignore_changes keeps subsequent applies
# from clobbering it and keeps the real key out of Terraform state/plan diffs.
resource "aws_secretsmanager_secret_version" "anthropic_api_key" {
  secret_id     = aws_secretsmanager_secret.anthropic_api_key.id
  secret_string = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_string]
  }
}
