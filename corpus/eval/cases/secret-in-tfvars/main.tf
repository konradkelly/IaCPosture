variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_db_instance" "app" {
  identifier          = "app-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = true
}
