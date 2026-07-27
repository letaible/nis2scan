###############################################################################
# Data Sources
###############################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

###############################################################################
# NR8-001: S3 Default Encryption
###############################################################################

resource "aws_s3_bucket" "compliant" {
  bucket        = "${var.name}-compliant-${var.suffix}"
  force_destroy = true

  tags = {
    Name  = "${var.name}-compliant-${var.suffix}"
    Check = "NR8-001"
    Role  = "compliant"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Non-compliant: no explicit encryption configuration.
# NOTE: Since Jan 2023 AWS auto-encrypts all new buckets with SSE-S3.
# The integration check may not detect this as non-compliant on real AWS.
resource "aws_s3_bucket" "non_compliant" {
  bucket        = "${var.name}-non-compliant-${var.suffix}"
  force_destroy = true

  tags = {
    Name  = "${var.name}-non-compliant-${var.suffix}"
    Check = "NR8-001"
    Role  = "non_compliant"
  }
}

###############################################################################
# NR8-002: EBS Volumes Encrypted
###############################################################################

resource "aws_ebs_volume" "compliant" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  type              = "gp3"
  encrypted         = true

  tags = {
    Name  = "${var.name}-ebs-compliant-${var.suffix}"
    Check = "NR8-002"
    Role  = "compliant"
  }
}

resource "aws_ebs_volume" "non_compliant" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  type              = "gp3"
  # Task #54 Szenario-Toggle. NOTE: aws_ebs_encryption_by_default stays
  # disabled at the account level in ALL scenarios (see root main.tf comment)
  # — only this volume's own encrypted flag moves, so the toggle never
  # touches account-wide default-encryption behavior for other resources.
  encrypted = var.fixture_compliance["nr8_ebs_encryption"]

  tags = {
    Name  = "${var.name}-ebs-non-compliant-${var.suffix}"
    Check = "NR8-002"
    Role  = "non_compliant"
  }
}

###############################################################################
# NR8-003: RDS Storage Encryption
###############################################################################

resource "aws_db_subnet_group" "this" {
  name       = "${var.name}-dbsubnet-${var.suffix}"
  subnet_ids = var.subnet_ids

  tags = {
    Name  = "${var.name}-dbsubnet-${var.suffix}"
    Check = "NR8-003"
  }
}

resource "random_password" "rds_compliant" {
  length  = 16
  special = false
}

resource "random_password" "rds_non_compliant" {
  length  = 16
  special = false
}

resource "aws_db_instance" "compliant" {
  identifier              = "${var.name}-rds-compliant-${var.suffix}"
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  storage_encrypted       = true
  username                = "admin"
  password                = random_password.rds_compliant.result
  db_subnet_group_name    = aws_db_subnet_group.this.name
  skip_final_snapshot     = true
  backup_retention_period = 0
  deletion_protection     = false

  tags = {
    Name  = "${var.name}-rds-compliant-${var.suffix}"
    Check = "NR8-003"
    Role  = "compliant"
  }
}

resource "aws_db_instance" "non_compliant" {
  identifier           = "${var.name}-rds-non-compliant-${var.suffix}"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = random_password.rds_non_compliant.result
  db_subnet_group_name = aws_db_subnet_group.this.name
  skip_final_snapshot  = true
  deletion_protection  = false

  # Task #54 Szenario-Toggles. This one RDS instance is the tracked fixture
  # for THREE independent §30-Checks; each attribute below moves on its own
  # fixture_compliance key so "mixed" can split them across areas:
  #   - storage_encrypted       -> AWS-NR8-003 (nr8_rds_encryption)
  #   - backup_retention_period -> AWS-NR3-001 (nr3_rds_backup_retention)
  # multi_az (AWS-NR3-004) is intentionally NOT toggled here — stays single-AZ
  # in all scenarios. Multi-AZ roughly doubles RDS cost and adds significant
  # provisioning/teardown time; see hardened_supported=false for
  # nr3_rds_multi_az in ../../outputs.tf.
  storage_encrypted       = var.fixture_compliance["nr8_rds_encryption"]
  backup_retention_period = var.fixture_compliance["nr3_rds_backup_retention"] ? 7 : 0

  tags = {
    Name  = "${var.name}-rds-non-compliant-${var.suffix}"
    Check = "NR8-003"
    Role  = "non_compliant"
  }
}

###############################################################################
# NR8-004: KMS Key Rotation
###############################################################################

resource "aws_kms_key" "compliant" {
  description             = "${var.name} compliant KMS key (rotation enabled)"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  tags = {
    Name  = "${var.name}-kms-compliant-${var.suffix}"
    Check = "NR8-004"
    Role  = "compliant"
  }
}

resource "aws_kms_key" "non_compliant" {
  description = "${var.name} non-compliant KMS key (rotation disabled)"
  # Task #54 Szenario-Toggle.
  enable_key_rotation     = var.fixture_compliance["nr8_kms_key_rotation"]
  deletion_window_in_days = 7

  tags = {
    Name  = "${var.name}-kms-non-compliant-${var.suffix}"
    Check = "NR8-004"
    Role  = "non_compliant"
  }
}

###############################################################################
# NR8-005: ALB TLS Policy
###############################################################################

# Self-signed TLS certificate for HTTPS listeners
resource "tls_private_key" "this" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "this" {
  private_key_pem = tls_private_key.this.private_key_pem

  subject {
    common_name  = "${var.name}-${var.suffix}.example.com"
    organization = "NIS2Scan Integration Test"
  }

  validity_period_hours = 24

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "aws_acm_certificate" "this" {
  private_key      = tls_private_key.this.private_key_pem
  certificate_body = tls_self_signed_cert.this.cert_pem

  tags = {
    Name  = "${var.name}-cert-${var.suffix}"
    Check = "NR8-005"
  }
}

# Security group for ALBs — allow inbound HTTPS (443)
resource "aws_security_group" "alb" {
  name        = "${var.name}-alb-sg-${var.suffix}"
  description = "Allow inbound HTTPS for NR8-005 ALB TLS integration tests"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name  = "${var.name}-alb-sg-${var.suffix}"
    Check = "NR8-005"
  }
}

# Compliant ALB — TLS 1.3 policy
resource "aws_lb" "compliant" {
  name               = "n2s-${var.suffix}-alb-c"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.subnet_ids

  tags = {
    Name  = "${var.name}-alb-compliant-${var.suffix}"
    Check = "NR8-005"
    Role  = "compliant"
  }
}

resource "aws_lb_listener" "compliant" {
  load_balancer_arn = aws_lb.compliant.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.this.arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }

  tags = {
    Name  = "${var.name}-listener-compliant-${var.suffix}"
    Check = "NR8-005"
    Role  = "compliant"
  }
}

# Non-compliant ALB — weak TLS policy (allows TLS 1.0)
resource "aws_lb" "non_compliant" {
  name               = "n2s-${var.suffix}-alb-nc"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.subnet_ids

  tags = {
    Name  = "${var.name}-alb-non-compliant-${var.suffix}"
    Check = "NR8-005"
    Role  = "non_compliant"
  }
}

resource "aws_lb_listener" "non_compliant" {
  load_balancer_arn = aws_lb.non_compliant.arn
  port              = 443
  protocol          = "HTTPS"
  # Task #54 Szenario-Toggle "nr8_alb_tls_policy": drives BOTH AWS-NR8-005
  # (deny-list of named insecure policies) and AWS-NR8-006 (protocol-based
  # TLS >=1.2 check) — both checks read this same ssl_policy string, so they
  # cannot move independently and share one fixture_compliance key.
  ssl_policy      = var.fixture_compliance["nr8_alb_tls_policy"] ? "ELBSecurityPolicy-TLS13-1-2-2021-06" : "ELBSecurityPolicy-2016-08"
  certificate_arn = aws_acm_certificate.this.arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }

  tags = {
    Name  = "${var.name}-listener-non-compliant-${var.suffix}"
    Check = "NR8-005"
    Role  = "non_compliant"
  }
}
