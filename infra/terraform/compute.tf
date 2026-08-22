resource "aws_instance" "honeytrace" {
	ami                  = "ami-02b1e514ef1cb3954"
	instance_type        = var.instance_type
	subnet_id            = aws_subnet.public.id
	associate_public_ip_address = false
	vpc_security_group_ids = [aws_security_group.honeytrace.id]
	iam_instance_profile = aws_iam_instance_profile.honeytrace.name
	user_data = <<-EOF
		#!/usr/bin/env bash
		exec > /var/log/honeytrace-userdata.log 2>&1
		set -euo pipefail

		if ! rpm -q amazon-ssm-agent >/dev/null 2>&1; then
		  dnf install -y https://s3.ap-south-1.amazonaws.com/amazon-ssm-ap-south-1/latest/linux_amd64/amazon-ssm-agent.rpm
		fi

		systemctl enable --now amazon-ssm-agent
		systemctl is-active --quiet amazon-ssm-agent
	EOF

	root_block_device {
		volume_size           = var.root_volume_size
		volume_type           = "gp3"
		encrypted             = true
		delete_on_termination = true
	}

	lifecycle {
		# These attributes would force an otherwise unnecessary instance replacement.
		# The live host already has its Elastic IP and a working SSM Agent.
		ignore_changes = [associate_public_ip_address, user_data]
	}

	tags = {
		Name = "${var.project_name}-honeypot"
	}
}

resource "aws_eip" "honeytrace" {
	domain = "vpc"

	tags = {
		Name = "${var.project_name}-eip"
	}
}

resource "aws_eip_association" "honeytrace" {
	instance_id   = aws_instance.honeytrace.id
	allocation_id = aws_eip.honeytrace.id
}
