resource "aws_cloudwatch_log_group" "plain" {
  name              = "/eval/plain"
  retention_in_days = 400
}
