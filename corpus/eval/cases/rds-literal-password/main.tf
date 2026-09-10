resource "aws_db_instance" "literal" {
  identifier          = "literal-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "Sup3rS3cretPassw0rd!"
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = true
}
