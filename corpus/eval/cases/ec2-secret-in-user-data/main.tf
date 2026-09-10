resource "aws_instance" "leaky" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

  user_data = <<-EOT
    #!/bin/bash
    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  EOT

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }
}
