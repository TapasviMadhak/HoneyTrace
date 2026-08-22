resource "aws_security_group" "honeytrace" {
  name        = "${var.project_name}-sg"
  description = "HoneyTrace bait SSH security group"
  vpc_id      = aws_vpc.honeytrace.id

  ingress {
    description = "Bait SSH on port 22 for Cowrie"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-sg"
  }
}
