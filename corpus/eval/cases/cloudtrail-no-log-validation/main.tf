resource "aws_cloudtrail" "unvalidated" {
  name                       = "unvalidated"
  s3_bucket_name             = "eval-trail-bucket"
  is_multi_region_trail      = true
  enable_log_file_validation = false
  kms_key_id                 = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
}
