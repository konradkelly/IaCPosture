resource "aws_cloudwatch_log_group" "forever" {
  name       = "/eval/forever"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
}
