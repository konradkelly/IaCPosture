resource "aws_cloudtrail" "single" {
  name                       = "single"
  s3_bucket_name             = "eval-trail-bucket"
  is_multi_region_trail      = false
  enable_log_file_validation = true
  kms_key_id                 = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
}
