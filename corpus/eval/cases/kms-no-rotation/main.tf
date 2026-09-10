resource "aws_kms_key" "static" {
  description         = "no rotation"
  enable_key_rotation = false
}
