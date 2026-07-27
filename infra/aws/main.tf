# ============================================================================
# nis2scan — Integration Test Infrastructure (AWS)
# ============================================================================
# Creates compliant AND non-compliant resources for each implemented check.
# Designed to be created and destroyed within a single CI pipeline run.
# ============================================================================

# --- Random suffix for unique resource names ---
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix = random_id.suffix.hex
  name   = "nis2scan-${local.suffix}"
}

# ============================================================================
# Szenario-Steuerung (Task #54): fixture_compliance je Fixture-Key
# ============================================================================
# Jeder Key entspricht GENAU einer unabhängig umschaltbaren Ressourcen-
# Konfiguration (siehe Kommentare in den jeweiligen Modulen). Zwei Keys steuern
# je ZWEI Check-IDs, weil beide Checks dieselbe physische Ressource/dasselbe
# Attribut auswerten und nicht unabhängig voneinander stehen können:
#   - nr3_s3_versioning_objectlock -> AWS-NR3-002 UND AWS-NR3-003 (S3 Object
#     Lock erfordert aktivierte Versionierung auf AWS-Seite; beide Zustände
#     würden sich sonst gegenseitig widersprechen).
#   - nr8_alb_tls_policy -> AWS-NR8-005 UND AWS-NR8-006 (beide lesen dieselbe
#     ssl_policy desselben Listeners).
#
# Fixtures OHNE eigenen Terraform-Toggle (rein Konto-globale Abwesenheits-
# Checks wie Config Recorder, SecurityHub, GuardDuty, Organizations/SCP,
# Backup Plans, Route 53 Health Checks, Trusted Advisor, VPN, Break-Glass —
# siehe Abschlussbericht Task #54) tauchen hier bewusst NICHT auf: kein Modul
# unter infra/aws/modules/* legt für sie eine Ressource an (nr4_lieferkette
# ist z.B. ein leeres Modul), es gibt also nichts zu invertieren. Sie bleiben
# unverändert Positive-Path-Tests in den bestehenden test_integration_nrX.py
# und laufen unverändert weiter — nur eben (wie alle "alten" Tests) ausschließ-
# lich im Szenario "gaps" (siehe SKIP_UNLESS_GAPS_SCENARIO).
locals {
  # "mixed": von Hand zugeteilt, angenähert hälftig (9/17 compliant) und über
  # die §30-Bereiche gestreut. KEIN Zufall, kein Hash (Gründer-Vorgabe).
  fixture_compliance_mixed = {
    nr1_cloudtrail_log_validation = true
    nr3_s3_versioning_objectlock  = false
    nr3_ebs_snapshot              = true
    nr3_rds_backup_retention      = false
    nr5_ecr_scan_on_push          = true
    nr5_lambda_runtime            = false
    nr6_log_retention             = true
    nr7_password_policy           = true
    nr8_ebs_encryption            = false
    nr8_rds_encryption            = true
    nr8_kms_key_rotation          = false
    nr8_alb_tls_policy            = true
    nr9_iam_mfa                   = false
    nr9_security_group            = true
    nr9_s3_account_pab            = false
    nr9_iam_wildcard_policy       = true
    nr10_console_mfa              = false
  }

  fixture_keys = keys(local.fixture_compliance_mixed)

  # scenario == "gaps"     -> alle Keys false (heutiges Verhalten, unverändert)
  # scenario == "hardened" -> alle Keys true
  # scenario == "mixed"    -> siehe fixture_compliance_mixed oben
  fixture_compliance = (
    var.scenario == "hardened" ? { for k in local.fixture_keys : k => true } :
    var.scenario == "mixed" ? local.fixture_compliance_mixed :
    { for k in local.fixture_keys : k => false }
  )
}

# --- Account identity ---
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# --- Disable EBS default encryption (so we can create unencrypted volumes) ---
# Task #54: this account-wide toggle stays DISABLED in ALL THREE scenarios,
# including "hardened". The per-volume "encrypted" attribute on the tracked
# NR8-002 fixture (see modules/nr8_kryptographie/main.tf) is what actually
# moves with the scenario — flipping this account-wide default instead would
# also silently re-encrypt every OTHER volume the CI account creates, masking
# whether checks correctly read the per-resource attribute rather than
# inheriting compliance for free from the account default. Same account-global
# singleton caveat as the IAM password policy and S3 account public access
# block (see comments in modules/nr7_cyberhygiene and modules/nr9_zugriffs-
# kontrolle): never run two scenarios' applies in parallel against one account.
resource "aws_ebs_encryption_by_default" "disable" {
  enabled = false
}

# --- Shared VPC for ALBs and Security Groups ---
resource "aws_vpc" "test" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${local.name}-vpc" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "az1" {
  vpc_id                  = aws_vpc.test.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = { Name = "${local.name}-subnet-az1" }
}

resource "aws_subnet" "az2" {
  vpc_id                  = aws_vpc.test.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false

  tags = { Name = "${local.name}-subnet-az2" }
}

resource "aws_internet_gateway" "test" {
  vpc_id = aws_vpc.test.id
  tags   = { Name = "${local.name}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.test.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.test.id
  }

  tags = { Name = "${local.name}-rt-public" }
}

resource "aws_route_table_association" "az1" {
  subnet_id      = aws_subnet.az1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "az2" {
  subnet_id      = aws_subnet.az2.id
  route_table_id = aws_route_table.public.id
}

# --- Module: Nr. 8 Kryptographie ---
module "nr8_kryptographie" {
  source = "./modules/nr8_kryptographie"

  suffix             = local.suffix
  name               = local.name
  vpc_id             = aws_vpc.test.id
  subnet_ids         = [aws_subnet.az1.id, aws_subnet.az2.id]
  region             = var.region
  fixture_compliance = local.fixture_compliance

  # The module creates the deliberately UNENCRYPTED EBS volume. Without this
  # ordering it races the account-wide default-encryption disable above —
  # if the volume wins the race while the default is still enabled, AWS
  # force-encrypts it and every NR8-002/exceptions integration test fails
  # (flaky since 13.07., first lost race 27.07.2026; nr3_bcm already had
  # this dependency, nr8 was missed).
  depends_on = [aws_ebs_encryption_by_default.disable]
}

# --- Module: Nr. 9 Zugriffskontrolle ---
module "nr9_zugriffskontrolle" {
  source = "./modules/nr9_zugriffskontrolle"

  suffix             = local.suffix
  name               = local.name
  vpc_id             = aws_vpc.test.id
  fixture_compliance = local.fixture_compliance
}

# --- Module: Nr. 10 MFA & Kommunikation ---
module "nr10_mfa_kommunikation" {
  source = "./modules/nr10_mfa_kommunikation"

  suffix             = local.suffix
  name               = local.name
  fixture_compliance = local.fixture_compliance
}

# --- Module: Nr. 1 Risikoanalyse ---
module "nr1_risikoanalyse" {
  source = "./modules/nr1_risikoanalyse"

  suffix             = local.suffix
  name               = local.name
  fixture_compliance = local.fixture_compliance
}

# --- Module: Nr. 3 Aufrechterhaltung des Betriebs (BCM) ---
module "nr3_bcm" {
  source = "./modules/nr3_bcm"

  suffix             = local.suffix
  name               = local.name
  fixture_compliance = local.fixture_compliance

  depends_on = [aws_ebs_encryption_by_default.disable]
}

# --- Module: Nr. 2 Bewältigung von Sicherheitsvorfällen ---
module "nr2_vorfallsbewaltigung" {
  source = "./modules/nr2_vorfallsbewaltigung"

  suffix = local.suffix
  name   = local.name
}

# --- Module: Nr. 5 Schwachstellenmanagement ---
module "nr5_schwachstellen" {
  source = "./modules/nr5_schwachstellen"

  suffix             = local.suffix
  name               = local.name
  fixture_compliance = local.fixture_compliance
}

# --- Module: Nr. 7 Cyberhygiene ---
module "nr7_cyberhygiene" {
  source = "./modules/nr7_cyberhygiene"

  suffix             = local.suffix
  name               = local.name
  fixture_compliance = local.fixture_compliance
}

# --- Module: Nr. 6 Wirksamkeit ---
module "nr6_wirksamkeit" {
  source = "./modules/nr6_wirksamkeit"

  suffix             = local.suffix
  name               = local.name
  fixture_compliance = local.fixture_compliance
}

# --- Module: Nr. 4 Lieferkette ---
module "nr4_lieferkette" {
  source = "./modules/nr4_lieferkette"

  suffix = local.suffix
  name   = local.name
}
