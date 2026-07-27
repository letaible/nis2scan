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

# --- Account identity ---
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# --- Disable EBS default encryption (so we can create unencrypted volumes) ---
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

  suffix     = local.suffix
  name       = local.name
  vpc_id     = aws_vpc.test.id
  subnet_ids = [aws_subnet.az1.id, aws_subnet.az2.id]
  region     = var.region

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

  suffix = local.suffix
  name   = local.name
  vpc_id = aws_vpc.test.id
}

# --- Module: Nr. 10 MFA & Kommunikation ---
module "nr10_mfa_kommunikation" {
  source = "./modules/nr10_mfa_kommunikation"

  suffix = local.suffix
  name   = local.name
}

# --- Module: Nr. 1 Risikoanalyse ---
module "nr1_risikoanalyse" {
  source = "./modules/nr1_risikoanalyse"

  suffix = local.suffix
  name   = local.name
}

# --- Module: Nr. 3 Aufrechterhaltung des Betriebs (BCM) ---
module "nr3_bcm" {
  source = "./modules/nr3_bcm"

  suffix = local.suffix
  name   = local.name

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

  suffix = local.suffix
  name   = local.name
}

# --- Module: Nr. 7 Cyberhygiene ---
module "nr7_cyberhygiene" {
  source = "./modules/nr7_cyberhygiene"

  suffix = local.suffix
  name   = local.name
}

# --- Module: Nr. 6 Wirksamkeit ---
module "nr6_wirksamkeit" {
  source = "./modules/nr6_wirksamkeit"

  suffix = local.suffix
  name   = local.name
}

# --- Module: Nr. 4 Lieferkette ---
module "nr4_lieferkette" {
  source = "./modules/nr4_lieferkette"

  suffix = local.suffix
  name   = local.name
}
