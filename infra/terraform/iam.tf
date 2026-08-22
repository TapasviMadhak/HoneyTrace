data "aws_iam_policy_document" "honeytrace_assume_role" {
	statement {
		actions = ["sts:AssumeRole"]

		principals {
			type        = "Service"
			identifiers = ["ec2.amazonaws.com"]
		}
	}
}

resource "aws_iam_role" "honeytrace" {
	name               = "${var.project_name}-instance-role"
	assume_role_policy = data.aws_iam_policy_document.honeytrace_assume_role.json

	tags = {
		Name = "${var.project_name}-instance-role"
	}
}

data "aws_iam_policy_document" "honeytrace_backup_write_only" {
	statement {
		actions = [
			"s3:AbortMultipartUpload",
			"s3:ListBucketMultipartUploads",
			"s3:ListMultipartUploadParts",
			"s3:PutObject",
		]

		resources = [
			"${aws_s3_bucket.backups.arn}",
			"${aws_s3_bucket.backups.arn}/*",
		]
	}
}

resource "aws_iam_role_policy" "honeytrace_backup_write_only" {
	name   = "${var.project_name}-backup-write-only"
	role   = aws_iam_role.honeytrace.id
	policy = data.aws_iam_policy_document.honeytrace_backup_write_only.json
}

data "aws_iam_policy_document" "honeytrace_telemetry_write_only" {
  statement {
    actions = ["s3:PutObject"]

    resources = [
      "${aws_s3_bucket.telemetry.arn}/${local.telemetry_export_prefix}/*",
    ]
  }
}

resource "aws_iam_role_policy" "honeytrace_telemetry_write_only" {
  name   = "${var.project_name}-telemetry-write-only"
  role   = aws_iam_role.honeytrace.id
  policy = data.aws_iam_policy_document.honeytrace_telemetry_write_only.json
}

resource "aws_iam_role_policy_attachment" "honeytrace_ssm_core" {
	role       = aws_iam_role.honeytrace.name
	policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "honeytrace" {
	name = "${var.project_name}-instance-profile"
	role = aws_iam_role.honeytrace.name
}
