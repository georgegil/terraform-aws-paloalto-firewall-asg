locals {
  asg_tags = [
    for item in keys(var.tags) :
    tomap({
      key                 = item
      value               = element(values(var.tags), index(keys(var.tags), item))
      propagate_at_launch = true
    })
  ]
}

resource "aws_key_pair" "keypair" {
  count = var.key_name == null ? 1 : 0

  key_name   = "${var.asg_name}-kp"
  public_key = var.keypair_public_key

  tags = var.tags
}

data "aws_ami" "ami" {
  most_recent = true
  owners      = ["679593333241"]

  filter {
    name   = "name"
    values = ["PA-VM-AWS-${var.pan_version}*"]
  }

  filter {
    name   = "product-code"
    values = ["6njl1pau431dv1qxipg63mvah"]
  }
}


data "aws_iam_role" "asg" {
  name = "AWSServiceRoleForAutoScaling_-CMK"
}

resource "aws_security_group" "sg" {
  count = var.security_groups == null ? 1 : 0

  name        = "${var.asg_name}-sg"
  description = "Allow access to instances in ASG ${var.asg_name}"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      from_port       = ingress.value.from_port
      to_port         = ingress.value.to_port
      protocol        = ingress.value.protocol
      cidr_blocks     = ingress.value.cidr_blocks
      security_groups = ingress.value.security_groups
      description     = ingress.value.description
      self            = ingress.value.self
    }
  }

  dynamic "egress" {
    for_each = var.egress_rules
    content {
      from_port       = egress.value.from_port
      to_port         = egress.value.to_port
      protocol        = egress.value.protocol
      cidr_blocks     = egress.value.cidr_blocks
      security_groups = egress.value.security_groups
      description     = egress.value.description
      self            = egress.value.self
    }
  }

  tags = merge({ "Name" = "${var.asg_name}-sg" }, var.tags)
}

resource "aws_launch_configuration" "lc" {
  name              = "${var.lc_name}-${replace("${timestamp()}", "/[- TZ:]/", "")}"
  image_id          = data.aws_ami.ami.id
  instance_type     = var.instance_type
  security_groups   = var.security_groups == null ? [aws_security_group.sg[0].id] : var.security_groups
  key_name          = var.key_name == null ? aws_key_pair.keypair[0].key_name : var.key_name
  user_data         = var.user_data
  enable_monitoring = var.enable_monitoring
  ebs_optimized     = true
  spot_price        = var.spot_price
  placement_tenancy = var.placement_tenancy

  iam_instance_profile        = var.iam_instance_profile
  associate_public_ip_address = var.associate_public_ip_address

  root_block_device {
    volume_size           = var.os_volume_size
    delete_on_termination = "true"
    volume_type           = var.os_volume_type
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes = [
      name
    ]
  }
}

resource "aws_autoscaling_group" "asg" {
  # Interpolating the LC name into the ASG name here causes any changes that
  # would replace the LC (like, most commonly, an AMI ID update) to _also_
  # replace the ASG.
  name             = "${var.asg_name}-on-${aws_launch_configuration.lc.name}"
  desired_capacity = var.desired_capacity
  max_size         = var.max_size
  min_size         = var.min_size

  default_cooldown     = var.default_cooldown
  launch_configuration = aws_launch_configuration.lc.name
  placement_group      = var.placement_group
  vpc_zone_identifier  = var.subnet_ids
  load_balancers       = var.load_balancers
  target_group_arns    = var.target_group_arns
  enabled_metrics      = var.enabled_metrics

  service_linked_role_arn   = data.aws_iam_role.asg.arn
  health_check_grace_period = var.health_check_grace_period
  health_check_type         = var.health_check_type
  wait_for_capacity_timeout = var.wait_for_capacity_timeout

  termination_policies = var.termination_policies
  suspended_processes  = var.suspended_processes

  min_elb_capacity      = var.min_elb_capacity
  wait_for_elb_capacity = var.wait_for_elb_capacity
  protect_from_scale_in = var.protect_from_scale_in
  max_instance_lifetime = var.max_instance_lifetime

  initial_lifecycle_hook {
    name                    = "add_eni"
    default_result          = "ABANDON"
    heartbeat_timeout       = 2000
    lifecycle_transition    = "autoscaling:EC2_INSTANCE_LAUNCHING"
    notification_target_arn = var.initial_lifecycle_notification_target_arn
    role_arn                = var.initial_lifecycle_role_arn
  }

  timeouts {
    delete = "15m"
  }

  tags = concat(
    [
      {
        key                 = "Name"
        value               = "${var.asg_name}"
        propagate_at_launch = true
      }
    ],
    local.asg_tags
  )
}
