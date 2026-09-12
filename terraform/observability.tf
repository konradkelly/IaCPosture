# Spec §4.1: custom metrics for findings-per-scan and fix acceptance, an alarm
# on scan failures, X-Ray end to end. Tracing itself is on each function
# (tracing_config) and its role (XRayWrite); this file is the metrics and the
# alarms.
#
# The custom metrics are emitted as CloudWatch Embedded Metric Format (EMF):
# the handler prints one JSON line with an `_aws` block and CloudWatch extracts
# the metric from the log stream. No PutMetricData call, no extra IAM, no SDK,
# and the log line is itself a readable record of the run. Nothing here has to
# be created for them -- the namespace appears on first emission.

# ---------- alarms ----------

resource "aws_sns_topic" "alarms" {
  name = "${var.project}-${var.environment}-alarms"
}

resource "aws_sns_topic_subscription" "alarm_email" {
  count = var.alarm_email == null ? 0 : 1

  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

locals {
  # Every function, not just the scanner. A mapping-agent or remediation-agent
  # error is the same shape of failure -- a finding stuck in a state a re-run
  # has to notice -- and one for_each is no dearer than one alarm.
  alarmed_functions = {
    terraform_scanner = aws_lambda_function.terraform_scanner.function_name
    mapping_agent     = aws_lambda_function.mapping_agent.function_name
    remediation_agent = aws_lambda_function.remediation_agent.function_name
    review_api        = aws_lambda_function.review_api.function_name
  }
}

# Any invocation error. For terraform-scanner this only became worth alarming
# on once ScannerError existed: before it, a crashed tfsec or checkov was
# swallowed into an empty result and the function returned 200, so this metric
# would never have moved.
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = local.alarmed_functions

  alarm_name          = "${each.value}-errors"
  alarm_description   = "${each.value} raised at least one invocation error in the last 5 minutes"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  # No invocations means no errors, not "unknown".
  treat_missing_data = "notBreaching"

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]
}

# remediation-agent is the one function that runs near its ceiling: the chain
# makes one model call and one self-check scan per finding, and a cold scanner
# is 60-100s of that. A run that stops just short of 900s is a run whose last
# findings were silently never reached.
resource "aws_cloudwatch_metric_alarm" "remediation_near_timeout" {
  alarm_name          = "${aws_lambda_function.remediation_agent.function_name}-near-timeout"
  alarm_description   = "remediation-agent ran within 10% of its timeout; later findings in the file may not have been reached"
  namespace           = "AWS/Lambda"
  metric_name         = "Duration"
  dimensions          = { FunctionName = aws_lambda_function.remediation_agent.function_name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = aws_lambda_function.remediation_agent.timeout * 1000 * 0.9
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alarms.arn]
}

output "alarms_topic_arn" {
  value = aws_sns_topic.alarms.arn
}
