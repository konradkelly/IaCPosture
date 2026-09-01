# Single-table design (spec §5): FindingRecord under PR#<id>/FINDING#<id>,
# ReviewEvent under FINDING#<id>/EVENT#<timestamp>. No GSIs yet — added when
# a concrete query pattern (e.g. control_id lookup) actually needs one.
resource "aws_dynamodb_table" "findings" {
  name         = "${var.project}-${var.environment}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }
}
