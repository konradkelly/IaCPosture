resource "aws_security_group" "wide" {
  name        = "wide"
  description = "everything"

  ingress {
    description = "all"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
