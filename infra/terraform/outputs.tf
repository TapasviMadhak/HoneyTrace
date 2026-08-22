output "project_name" {
  value = var.project_name
}

output "aws_region" {
  value = var.aws_region
}

output "vpc_id" {
  value = aws_vpc.honeytrace.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "security_group_id" {
  value = aws_security_group.honeytrace.id
}

output "instance_id" {
  value = aws_instance.honeytrace.id
}

output "instance_public_ip" {
  value = aws_eip.honeytrace.public_ip
}

output "elastic_ip_allocation_id" {
  value = aws_eip.honeytrace.id
}

output "backup_bucket_name" {
  value = aws_s3_bucket.backups.bucket
}

output "backup_bucket_arn" {
  value = aws_s3_bucket.backups.arn
}

output "instance_role_name" {
  value = aws_iam_role.honeytrace.name
}

output "telemetry_bucket_name" {
  value = aws_s3_bucket.telemetry.bucket
}

output "telemetry_cloudfront_oai_path" {
  value = aws_cloudfront_origin_access_identity.telemetry.cloudfront_access_identity_path
}
