resource "aws_security_group" "ssh" {
  name        = "ssh"
  description = "SSH access"

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
