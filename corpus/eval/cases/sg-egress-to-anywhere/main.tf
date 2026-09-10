resource "aws_security_group" "out" {
  name        = "out"
  description = "unrestricted egress"

  egress {
    description = "all out"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
