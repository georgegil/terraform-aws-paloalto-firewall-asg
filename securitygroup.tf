# ---------------------------------------------------------------------------------------------------------------------
# CREATE SECURITY GROUPS
# 2 SG (FW MGMT, FW DATA)
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_security_group" "dns_sg" {
  name        = local.dns_sg_name
  description = "Allow communication to DNS servers"
  vpc_id      = aws_vpc.vpc.id

  tags = merge({ "Name" = local.dns_sg_name }, var.tags)
}

resource "aws_security_group" "fw-mgmt-sg" {
  name        = "fw-mgmt-sg"
  description = "Allow inbound traffic only from Palo Alto Networks"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["81.187.183.21/32", "10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge({ "Name" = "Management-SG" }, var.tags)


}

resource "aws_security_group" "fw-data-sg" {
  name        = "fw-data-sg"
  description = "Allow inbound traffic only from GWLB"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 6081
    to_port     = 6081
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags

  depends_on = [aws_vpc.vpc]
}

resource "aws_security_group" "lambda-sg" {
  name        = "lamda"
  description = "Allow Lamda function to communicate outbound"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge({ "Name" = "lambda-sg" }, var.tags)


}

resource "aws_security_group" "s3_intf_sg" {
  name        = "Transit-s3-endpoint-sg"
  description = "Created for S3 Interface VPC Endpoint"
  vpc_id      = aws_vpc.vpc.id

  tags = merge({ "Name" = "Transit-s3-endpoint-sg" }, var.tags)
}

resource "aws_security_group_rule" "s3_intf_sg_inbound" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.s3_intf_sg.id
}

resource "aws_security_group_rule" "s3_intf_sg_outbound" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.s3_intf_sg.id
}