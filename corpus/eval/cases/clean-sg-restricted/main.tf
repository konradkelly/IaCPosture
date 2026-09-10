resource "aws_security_group" "tight" {
  name        = "tight"
  description = "Internal SSH from the corporate range only"

  ingress {
    description = "ssh from corp"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }

  egress {
    description = "https to the VPC endpoint range"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

# Attached to something, because an orphaned security group is itself a
# finding (CKV2_AWS_5) and this control is meant to raise nothing.
resource "aws_network_interface" "eth0" {
  subnet_id       = "subnet-0123456789abcdef0"
  security_groups = [aws_security_group.tight.id]
}
