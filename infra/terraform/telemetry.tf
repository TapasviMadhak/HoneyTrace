locals {
  telemetry_bucket_name = "${var.project_name}-telemetry-public-${data.aws_caller_identity.current.account_id}"
  telemetry_export_prefix = "public"
}

resource "aws_s3_bucket" "telemetry" {
  bucket = local.telemetry_bucket_name

  tags = {
    Name = "${var.project_name}-telemetry-public"
  }
}

resource "aws_s3_bucket_ownership_controls" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "telemetry" {
  bucket                  = aws_s3_bucket.telemetry.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_cloudfront_origin_access_identity" "telemetry" {
  comment = "HoneyTrace telemetry bucket read access"
}

data "aws_iam_policy_document" "telemetry_bucket" {
  statement {
    sid     = "AllowCloudFrontOAIReadOnly"
    effect  = "Allow"
    actions = ["s3:GetObject"]

    principals {
      type        = "CanonicalUser"
      identifiers = [aws_cloudfront_origin_access_identity.telemetry.s3_canonical_user_id]
    }

    resources = ["${aws_s3_bucket.telemetry.arn}/*"]
  }
}

resource "aws_s3_bucket_policy" "telemetry" {
  bucket = aws_s3_bucket.telemetry.id
  policy = data.aws_iam_policy_document.telemetry_bucket.json
}
