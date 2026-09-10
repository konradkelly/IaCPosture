resource "aws_db_instance" "plain" {
  identifier          = "plain-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = false
  publicly_accessible = false
  skip_final_snapshot = true
}

variable "db_password" {
  type      = string
  sensitive = true
}
