resource "aws_launch_template" "web" {
  name          = "web"
  image_id      = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

  network_interfaces {
    associate_public_ip_address = true
  }

  metadata_options {
    http_tokens = "required"
  }
}
