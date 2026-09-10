resource "aws_db_instance" "public" {
  identifier          = "public-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = var.db_password
  publicly_accessible = true
  storage_encrypted   = true
  skip_final_snapshot = true
}

variable "db_password" {
  type      = string
  sensitive = true
}
