resource "aws_secretsmanager_secret" "rds_master" {
  name        = "dast/poc/rds/master"
  description = "DAST scanner POC RDS master credentials"
}

resource "aws_secretsmanager_secret_version" "rds_master" {
  secret_id = aws_secretsmanager_secret.rds_master.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db_master.result
    host     = aws_db_instance.main.address
    port     = aws_db_instance.main.port
    dbname   = var.db_name
  })
}
