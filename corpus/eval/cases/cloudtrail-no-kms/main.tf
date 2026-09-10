resource "aws_cloudtrail" "plain" {
  name                          = "plain"
  s3_bucket_name                = "eval-trail-bucket"
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
}
