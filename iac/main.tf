# DEMO IaC for the security pipeline — intentionally insecure patterns.
# checkov will report these; fix directions are in comments.

# Insecure: 0.0.0.0/0 SSH ingress (checkov CKV_AWS_24 / CKV2_AWS_5)
resource "aws_security_group" "app_sg" {
  name        = "app-sg"
  description = "demo insecure group"
}

resource "aws_security_group_rule" "ssh_open" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app_sg.id
}

# Insecure: unencrypted S3 bucket (checkov CKV_AWS_18 / CKV_AWS_19/20/21)
resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-app-data-bucket"
}
