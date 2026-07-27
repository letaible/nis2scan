# ============================================================================
# Nr. 5 — Schwachstellenmanagement (Vulnerability Management)
# ============================================================================
# NR5-001: ECR Image Scanning (scan_on_push)
# ============================================================================

# ---------------------------------------------------------------------------
# NR5-001: ECR Repository — Compliant (scan on push enabled)
# ---------------------------------------------------------------------------

resource "aws_ecr_repository" "compliant" {
  name                 = "${var.name}-ecr-compliant"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name  = "${var.name}-ecr-compliant"
    Check = "NR5-001"
    Role  = "compliant"
  }
}

# ---------------------------------------------------------------------------
# NR5-001: ECR Repository — Non-compliant (scan on push disabled)
# ---------------------------------------------------------------------------

resource "aws_ecr_repository" "non_compliant" {
  name                 = "${var.name}-ecr-non-compliant"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    # Task #54 Szenario-Toggle.
    scan_on_push = var.fixture_compliance["nr5_ecr_scan_on_push"]
  }

  tags = {
    Name  = "${var.name}-ecr-non-compliant"
    Check = "NR5-001"
    Role  = "non_compliant"
  }
}

# ---------------------------------------------------------------------------
# NR5-004: Lambda Runtime Versions
# ---------------------------------------------------------------------------

# --- IAM Role for Lambda ---
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.name}-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json

  tags = {
    Name    = "${var.name}-lambda-exec"
    Check   = "NR5-004"
    Purpose = "Lambda execution role for integration tests"
  }
}

# --- Dummy Lambda code (inline zip) ---
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda.zip"

  source {
    content  = "def handler(event, context): return {'statusCode': 200}"
    filename = "index.py"
  }
}

# --- Compliant: Lambda with current runtime ---
resource "aws_lambda_function" "compliant" {
  function_name = "${var.name}-lambda-compliant"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = data.archive_file.lambda_zip.output_path

  tags = {
    Name  = "${var.name}-lambda-compliant"
    Check = "NR5-004"
    Role  = "compliant"
  }
}

# --- Non-compliant: Lambda with deprecated runtime ---
resource "aws_lambda_function" "non_compliant_lambda" {
  function_name = "${var.name}-lambda-deprecated"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  # Task #54 Szenario-Toggle: "hardened"/"mixed" switch to the same current
  # runtime as the compliant function above.
  runtime  = var.fixture_compliance["nr5_lambda_runtime"] ? "python3.12" : "python3.8"
  filename = data.archive_file.lambda_zip.output_path

  tags = {
    Name  = "${var.name}-lambda-deprecated"
    Check = "NR5-004"
    Role  = "non_compliant"
  }
}
