resource "aws_security_group" "rdp" {
  name        = "rdp"
  description = "RDP access"

  ingress {
    description = "rdp"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
