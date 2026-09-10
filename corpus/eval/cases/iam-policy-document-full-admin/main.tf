data "aws_iam_policy_document" "admin" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "from_doc" {
  name   = "from-doc"
  policy = data.aws_iam_policy_document.admin.json
}
