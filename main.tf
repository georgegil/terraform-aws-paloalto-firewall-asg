

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}

###################
# Create VPC
###################

resource "aws_vpc" "vpc" {
  cidr_block                       = var.vpc_cidr
  enable_dns_hostnames             = true
  enable_dns_support               = true
  instance_tenancy                 = "default"
  assign_generated_ipv6_cidr_block = false
  tags                             = merge({ "Name" = "TRANSIT-${local.environment}${local.region_code}VPC" }, var.tags)
}

###################
# DHCP Options Set
###################
resource "aws_vpc_dhcp_options" "dhcp" {
  domain_name         = element(var.domain_name, 0)
  domain_name_servers = ["AmazonProvidedDNS"]
  ntp_servers         = var.dns_server

  tags = merge({ "Name" = local.dhcp_environment }, var.tags)
}

###################
# DNS routing
###################


resource "aws_route53_resolver_endpoint" "dns" {
  security_group_ids = [aws_security_group.dns_sg.id]
  name               = "${local.region_code}-dns"
  direction          = "OUTBOUND"

  dynamic "ip_address" {
    for_each = aws_subnet.mgmt[*].id
    content {
      subnet_id = ip_address.value
    }
  }

  tags = var.tags
}

resource "aws_route53_resolver_rule" "dns_fwd" {
  count                = length(var.domain_name)
  domain_name          = var.domain_name[count.index]
  name                 = replace("${local.region_code}-${var.domain_name[count.index]}", ".", "-")
  rule_type            = "FORWARD"
  resolver_endpoint_id = aws_route53_resolver_endpoint.dns.id

  dynamic "target_ip" {
    for_each = var.dns_server
    content {
      ip = target_ip.value
    }
  }

  tags = var.tags
}

resource "aws_route53_resolver_rule_association" "dns_routing_vpc" {
  count            = length(var.domain_name)
  resolver_rule_id = element(aws_route53_resolver_rule.dns_fwd[*].id, count.index)
  vpc_id           = aws_vpc.vpc.id
}

###################
# Internet Gateway
###################
resource "aws_internet_gateway" "internet_gw" {
  vpc_id = aws_vpc.vpc.id

  tags = merge({ "Name" = "TRANSIT-${local.environment}${local.region_code}-IGW" }, var.tags)
}

###################
# Subnets
###################
resource "aws_subnet" "mgmt" {
  count             = 3
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 0)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = merge({ "Name" = format("TRANSIT-${local.environment}${local.region_code}ManagementPlaneSubnetAZ%01d", count.index + 1) }, var.tags)
}

resource "aws_subnet" "data_routing" {
  count             = 3
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 3)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = merge({ "Name" = format("TRANSIT-${local.environment}${local.region_code}DataPlaneSubnetAZ%01d", count.index + 1) }, var.tags)
}

resource "aws_subnet" "endpoint_subnet" {
  count             = 3
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 6)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = merge({ "Name" = format("TRANSIT-${local.environment}${local.region_code}GatewayEndPointSubnetAZ%01d", count.index + 1) }, var.tags)
}

resource "aws_subnet" "tgw_subnet" {
  count             = 3
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 9)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = merge({ "Name" = format("TRANSIT-${local.environment}${local.region_code}TransitGatewaySubnetAZ%01d", count.index + 1) }, var.tags)
}

resource "aws_subnet" "egress_subnet" {
  count             = 3
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + 12)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = merge({ "Name" = format("TRANSIT-${local.environment}${local.region_code}NATEgressSubnetAZ%01d", count.index + 1) }, var.tags)
}


resource "aws_eip" "natgw_eip" {
  count = 3
  vpc   = true
  tags  = var.tags
}

resource "aws_nat_gateway" "nat_gw" {
  count         = 3
  allocation_id = aws_eip.natgw_eip[count.index].id
  subnet_id     = aws_subnet.egress_subnet[count.index].id

  tags = merge({ "Name" = format("TRANSIT-${local.environment}${local.region_code}NAT-GatewayAZ%01d", count.index + 1) }, var.tags)

}

###########################
# Route Tables and routes
###########################

resource "aws_route_table" "data-rt" {
  count  = 3
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw[count.index].id
  }

  route {
    cidr_block         = "10.0.0.0/8"
    transit_gateway_id = var.primary_transit_gw_id
  }

  dynamic "route" {
    for_each = var.spoke_vpc
    content {
      cidr_block         = route.value.vpc_cidr
      transit_gateway_id = route.value.transit_gw_id
    }
  }

  tags = merge({ "Name" = format("TRANSIT-${local.environment}${local.region_code}DataRoutingTblAZ%01d", count.index + 1) }, var.tags)

}

resource "aws_route_table_association" "mgmt-rt-association" {
  count          = 3
  subnet_id      = aws_subnet.mgmt[count.index].id
  route_table_id = aws_route_table.data-rt[count.index].id
}

resource "aws_route_table_association" "endpoint-rt-association" {
  count          = 3
  subnet_id      = aws_subnet.endpoint_subnet[count.index].id
  route_table_id = aws_route_table.data-rt[count.index].id
}

resource "aws_route_table_association" "data-rt-association" {
  count          = 3
  subnet_id      = aws_subnet.data_routing[count.index].id
  route_table_id = aws_route_table.data-rt[count.index].id
}


resource "aws_route_table" "egress_rt" {
  count  = 3
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.internet_gw.id
  }

  route {
    cidr_block         = "10.0.0.0/8"
    transit_gateway_id = var.primary_transit_gw_id
  }

  dynamic "route" {
    for_each = var.spoke_vpc
    content {
      cidr_block      = route.value.vpc_cidr
      vpc_endpoint_id = aws_vpc_endpoint.gateway[count.index].id
    }
  }

  tags = merge({ "Name" = format("TRANSIT-${local.environment}${local.region_code}EgressRoutingTableAZ%01d", count.index + 1) }, var.tags)


}

resource "aws_route_table_association" "egress-rt-association" {
  count     = 3
  subnet_id = aws_subnet.egress_subnet[count.index].id

  route_table_id = aws_route_table.egress_rt[count.index].id

}

###############################################
# Retrieve data on TGW and link to transit VPC
###############################################

data "aws_ec2_transit_gateway" "panw-tgw" {
  for_each = var.spoke_vpc
  id       = each.value.transit_gw_id

}

resource "aws_ec2_transit_gateway_vpc_attachment" "tgw_as" {
  for_each                                        = var.spoke_vpc
  subnet_ids                                      = aws_subnet.tgw_subnet[*].id
  transit_gateway_id                              = data.aws_ec2_transit_gateway.panw-tgw[each.key].id
  vpc_id                                          = aws_vpc.vpc.id
  transit_gateway_default_route_table_association = "true"
  transit_gateway_default_route_table_propagation = "true"
  appliance_mode_support                          = "enable"

  tags = merge({ "Name" = "${local.environment}${local.region_code}-TRANSIT-TGW-Attach-${each.key}" }, var.tags)

}

data "aws_ec2_transit_gateway_route_table" "tgw_transit_rt" {
  for_each = var.spoke_vpc
  filter {
    name   = "transit-gateway-id"
    values = [data.aws_ec2_transit_gateway.panw-tgw[each.key].id]
  }
}

resource "aws_ec2_transit_gateway_route" "egress" {
for_each = var.spoke_vpc
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.tgw_as[each.key].id
  transit_gateway_route_table_id = data.aws_ec2_transit_gateway_route_table.tgw_transit_rt[each.key].id
}


resource "aws_route_table" "tgwa-rt" {
  count  = 3
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block         = "10.0.0.0/8"
    transit_gateway_id = var.primary_transit_gw_id
  }

  route {
    cidr_block      = "0.0.0.0/0"
    vpc_endpoint_id = aws_vpc_endpoint.gateway[count.index].id
  }

  tags = merge({ "Name" = format("TRANSIT-${local.environment}${local.region_code}TransitGatewayRoutingTbl%01d", count.index + 1) }, var.tags)


}

resource "aws_route_table_association" "tgwa-rt-association" {
  count     = 3
  subnet_id = aws_subnet.tgw_subnet[count.index].id

  route_table_id = aws_route_table.tgwa-rt[count.index].id

  depends_on = [aws_route_table.tgwa-rt]
}

###################
# GWLB Endpoint
###################


resource "aws_vpc_endpoint_service" "gateway_endpoint" {
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.gateway_lb.arn]
}

resource "aws_vpc_endpoint" "gateway" {
  count             = 3
  service_name      = aws_vpc_endpoint_service.gateway_endpoint.service_name
  subnet_ids        = [aws_subnet.endpoint_subnet[count.index].id]
  vpc_endpoint_type = aws_vpc_endpoint_service.gateway_endpoint.service_type
  vpc_id            = aws_vpc.vpc.id

  lifecycle {
    ignore_changes = [subnet_ids]
  }

  tags = merge({ "Name" = format("TRANSIT-${local.environment}${local.region_code}GatewayEndpoint%01d", count.index + 1) }, var.tags)
}

###################################
# IAM Policy for Firewall instances
###################################


resource "aws_iam_role" "fw-iam-role" {
  name = "${data.aws_region.current.name}-firewall-role"
  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : "sts:AssumeRole",
          "Principal" : {
            "Service" : "ec2.amazonaws.com"
          },
          "Effect" : "Allow",
          "Sid" : ""
        }
      ]
    }
  )

  tags = var.tags

}

resource "aws_iam_policy" "fw-iam-policy" {
  name        = "${data.aws_region.current.name}-firewall-policy"
  path        = "/"
  description = "IAM Policy for Palo Alto Firewall"

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : "s3:ListBucket",
          "Resource" : "arn:aws:s3:::${module.bucket.bucket.bucket}",
          "Effect" : "Allow"
        },
        {
          "Action" : "s3:GetObject",
          "Resource" : "arn:aws:s3:::${module.bucket.bucket.bucket}/*"
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "ec2:AttachNetworkInterface",
            "ec2:DetachNetworkInterface",
            "ec2:DescribeInstances",
            "ec2:DescribeNetworkInterfaces"
          ],
          "Resource" : [
            "*"
          ],
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "logs:CreateLogGroup",
            "logs:CreateLogStream"
          ],
          "Resource" : [
            "*"
          ],
          "Effect" : "Allow"
        },
        {
          "Action" : [
            "cloudwatch:*"
          ],
          "Resource" : [
            "*"
          ],
          "Effect" : "Allow"
        }
      ]
    }
  )

  tags = var.tags

}

resource "aws_iam_role_policy_attachment" "policy-attachment" {
  role       = aws_iam_role.fw-iam-role.name
  policy_arn = aws_iam_policy.fw-iam-policy.arn
}

resource "aws_iam_instance_profile" "iam-instance-profile" {
  name = "iam-profile-firewall"
  role = aws_iam_role.fw-iam-role.name
  tags = var.tags
}

resource "aws_secretsmanager_secret" "pan_api" {
  name = "pan_api_key"
  tags = var.tags
}

resource "aws_secretsmanager_secret_policy" "api_policy" {
  secret_arn = aws_secretsmanager_secret.pan_api.arn

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Sid" : "EnableAllPermissions",
          "Effect" : "Allow",
          "Principal" : {
            "AWS" : aws_iam_role.lambda_execution_role.arn
          },
          "Action" : "secretsmanager:GetSecretValue",
          "Resource" : "*"
        }
      ]
    }
  )
}

resource "aws_secretsmanager_secret_version" "pan_api" {
  secret_id     = aws_secretsmanager_secret.pan_api.id
  secret_string = var.pan_api_key
}

module "ec2-asg" {
  source = "./custom_modules/asg"

  tags = var.tags

  ### Launch Configuration ###
  asg_name           = "transit-egress-firewall"
  lc_name            = "transit-egress-firewall"
  keypair_public_key = var.public_key
  key_name           = null
  user_data          = "vmseries-bootstrap-aws-s3bucket=${module.bucket.bucket.bucket}"
  pan_version        = var.pan_version
  vpc_id             = aws_vpc.vpc.id
  subnet_ids         = aws_subnet.data_routing[*].id
  instance_type      = var.instance_type
  security_groups    = null
  os_volume_size     = "75"
  os_volume_type     = "gp2"
  enable_monitoring  = true
  spot_price         = null
  placement_tenancy  = "default"

  iam_instance_profile        = aws_iam_instance_profile.iam-instance-profile.id
  associate_public_ip_address = false

  ### Autoscale Configuration ###
  desired_capacity  = length(var.availability_zones)
  max_size          = length(var.availability_zones)
  min_size          = 1
  default_cooldown  = 300
  placement_group   = null
  load_balancers    = []
  target_group_arns = [aws_lb_target_group.lb_target.arn]
  enabled_metrics   = null

  health_check_grace_period = 960
  health_check_type         = "EC2"
  wait_for_capacity_timeout = "10m"

  termination_policies = null
  suspended_processes  = null

  ## Custom Options ##
  min_elb_capacity      = null
  wait_for_elb_capacity = null
  protect_from_scale_in = false
  max_instance_lifetime = null

  initial_lifecycle_notification_target_arn = aws_sns_topic.lamda_asg_sns.arn
  initial_lifecycle_role_arn                = aws_iam_role.asg_notifier_role.arn



  ingress_rules = {
    internal = {
      from_port       = "0"
      to_port         = "0"
      protocol        = "-1"
      cidr_blocks     = ["10.0.0.0/8"]
      security_groups = []
      description     = "Allow all internal traffic inbound"
      self            = false
    }
  }

  egress_rules = {
    any = {
      from_port       = "0"
      to_port         = "0"
      protocol        = "-1"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      description     = "Allow any outbound"
      self            = false
    }
  }
}

resource "aws_lb" "gateway_lb" {
  name                             = "transit-firewall-lb"
  internal                         = false
  load_balancer_type               = "gateway"
  subnets                          = aws_subnet.data_routing[*].id
  enable_cross_zone_load_balancing = true

  enable_deletion_protection = false

  tags = var.tags
}

resource "aws_lb_target_group" "lb_target" {
  name     = "transit-firewalls"
  port     = 6081
  protocol = "GENEVE"
  vpc_id   = aws_vpc.vpc.id

  health_check {
    port     = 80
    protocol = "HTTP"
  }

}


resource "aws_lb_listener" "lb_listener" {
  load_balancer_arn = aws_lb.gateway_lb.id

  default_action {
    target_group_arn = aws_lb_target_group.lb_target.id
    type             = "forward"
  }


}

module "bucket" {

  source  = "./custom_modules/bucket"


  tags = var.tags

  bucket_name = "${data.aws_region.current.name}-palo-bootstrap"
  bucket_acl  = "private"

  kms_encrypted = true
  kms_key_arn   = null

  block_public_access = true
  enable_versioning   = false

  current_version_transitions = {
    WholeBucket_Current_DeleteOldVersions = {
      enabled         = true
      prefix          = ""
      storage_class   = "INTELLIGENT_TIERING"
      transition_days = 1
    }
  }

  current_version_expirations = {
    WholeBucket_Current_DeleteCurrentVersions = {
      enabled         = true
      prefix          = ""
      expiration_days = 365
    }
  }


  previous_version_transitions = {
    WholeBucket_Previous_ONEZONE_IA = {
      enabled         = true
      prefix          = ""
      storage_class   = "ONEZONE_IA"
      transition_days = 90
    }
  }

  previous_version_expirations = {
    WholeBucket_Previous_DeleteOldVersions = {
      enabled         = true
      prefix          = ""
      expiration_days = 180
    }
  }

  crr_role_arn        = null
  crr_dest_bucket_arn = null
  crr_configuration   = null
}

resource "aws_s3_bucket_policy" "b" {
  bucket = module.bucket.bucket.id

  depends_on = [
    module.bucket
  ]

  policy = jsonencode({
    "Id" : "Policy1629806463809",
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "palo",
        "Action" : "s3:*",
        "Effect" : "Allow",
        "Resource" : [
          module.bucket.bucket.arn,
          "${module.bucket.bucket.arn}/*"
        ]
        "Principal" : {
          "AWS" : [
            aws_iam_role.fw-iam-role.arn
          ]
        }
      }
    ]
  })
}

resource "aws_s3_bucket_object" "bootstrap_dirs" {
  for_each = toset([
    "config/",
    "content/",
    "software/",
    "license/",
    "plugins/",
    "lamba/"
  ])

  bucket  = module.bucket.bucket.id
  key     = each.value
  content = "/dev/null"
}

resource "aws_s3_bucket_object" "init_cfg" {
  bucket = module.bucket.bucket.id
  key    = "config/init-cfg.txt"
  content = templatefile("${path.module}/files/init-cfg.txt.tmpl", {
    "hostname"        = var.hostname,
    "panorama-server" = var.panorama-server,
    "tplname"         = var.tplname,
    "dgname"          = var.dgname,
    "dns-primary"     = var.dns-primary,
    "dns-secondary"   = var.dns-secondary,
    "vm-auth-key"     = var.vm-auth-key
  })
}

resource "aws_s3_bucket_object" "bootstrap_xml" {
  bucket = module.bucket.bucket.id
  key    = "config/bootstrap.xml"
  content = templatefile("${path.module}/files/bootstrap.xml",
    {
      "fw-logs"         = var.hostname
      "timezone"        = lookup(local.timezone, data.aws_region.current.name, "US/Central")
      "hostname"        = var.hostname
      "panorama-server" = var.panorama-server
    }
  )
}


resource "aws_s3_bucket_object" "plugin" {
  for_each = fileset("${path.module}/files/plugins/", "*")
  bucket   = module.bucket.bucket.id
  key      = "plugins/${each.key}"
  source   = "${path.module}/files/plugins/${each.key}"
}

resource "aws_s3_bucket_object" "content" {
  for_each = fileset("${path.module}/files/content/", "*")
  bucket   = module.bucket.bucket.id
  key      = "content/${each.key}"
  source   = "${path.module}/files/content/${each.key}"
}

resource "aws_s3_bucket_object" "authcodes" {
  bucket = module.bucket.bucket.id
  key    = "license/authcodes"
  content = templatefile("${path.module}/files/authcodes.txt",
    {
      "pan_os_authcode" = var.pan_os_authcode
    }
  )
}



resource "aws_vpc_endpoint" "private-s3" {
  vpc_id       = aws_vpc.vpc.id
  service_name = "com.amazonaws.${data.aws_region.current.name}.s3"
  route_table_ids = [
    aws_vpc.vpc.main_route_table_id,
    aws_route_table.data-rt[0].id,
    aws_route_table.data-rt[1].id,
    aws_route_table.data-rt[2].id,
    aws_route_table.egress_rt[0].id,
    aws_route_table.egress_rt[1].id,
    aws_route_table.egress_rt[2].id,

  ]
  tags   = merge({ "Name" = "EP-S3" }, var.tags)
  policy = <<POLICY
{
    "Statement": [
        {
            "Action": "*",
            "Effect": "Allow",
            "Resource": "*",
            "Principal": "*"
        }
    ],
    "Version": "2008-10-17"
}
POLICY
}

resource "aws_vpc_endpoint" "s3-intf" {
  vpc_id             = aws_vpc.vpc.id
  service_name       = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type  = "Interface"
  security_group_ids = [aws_security_group.s3_intf_sg.id]
  subnet_ids = [
    aws_subnet.mgmt[0].id,
    aws_subnet.mgmt[1].id,
    aws_subnet.mgmt[2].id
  ]
  tags                = merge({ "Name" = "EP-S3INTF" }, var.tags)
  private_dns_enabled = false
}



resource "aws_iam_role" "lambda_execution_role" {
  name = "${data.aws_region.current.name}-lambda_execution_role"

  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Effect" : "Allow",
          "Principal" : {
            "Service" : "lambda.amazonaws.com"
          },
          "Action" : "sts:AssumeRole"
        }
      ]
    }
  )
}

resource "aws_iam_role_policy" "lambda_execution_policy" {
  name = "${data.aws_region.current.name}-lambda_execution_policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Action" : "s3:ListBucket",
          "Resource" : module.bucket.bucket.arn
          "Effect" : "Allow"
        },
        {
          "Action" : "secretsmanager:ListSecrets"
          "Resource" : "*"
          "Effect" : "Allow"
        },
        {
          "Action" : "secretsmanager:GetSecretValue"
          "Resource" : aws_secretsmanager_secret.pan_api.arn
          "Effect" : "Allow"
        },
        {
          "Action" : "s3:GetObject",
          "Resource" : "${module.bucket.bucket.arn}/*"
          "Effect" : "Allow"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "ec2:AllocateAddress",
            "ec2:AssociateAddress",
            "ec2:AssociateRouteTable",
            "ec2:AttachInternetGateway",
            "ec2:AttachNetworkInterface",
            "ec2:CreateNetworkInterface",
            "ec2:CreateTags",
            "ec2:DeleteNetworkInterface",
            "ec2:DeleteRouteTable",
            "ec2:DeleteSecurityGroup",
            "ec2:DeleteTags",
            "ec2:DescribeAddresses",
            "ec2:DescribeAvailabilityZones",
            "ec2:DescribeInstanceAttribute",
            "ec2:DescribeInstanceStatus",
            "ec2:DescribeInstances",
            "ec2:DescribeImages",
            "ec2:DescribeNatGateways",
            "ec2:DescribeNetworkInterfaceAttribute",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeTags",
            "ec2:DescribeVpcEndpoints",
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets",
            "ec2:DescribeSecurityGroups",
            "ec2:DetachInternetGateway",
            "ec2:DetachNetworkInterface",
            "ec2:DetachVolume",
            "ec2:DisassociateAddress",
            "ec2:DisassociateRouteTable",
            "ec2:ModifyNetworkInterfaceAttribute",
            "ec2:ModifySubnetAttribute",
            "ec2:MonitorInstances",
            "ec2:RebootInstances",
            "ec2:ReleaseAddress",
            "ec2:ReportInstanceStatus",
            "ec2:TerminateInstances",
            "ec2:DescribeIdFormat"
          ],
          "Resource" : [
            "*"
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "events:*"
          ],
          "Resource" : [
            "*"
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "cloudwatch:*"
          ],
          "Resource" : [
            "*"
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "lambda:AddPermission",
            "lambda:CreateEventSourceMapping",
            "lambda:CreateFunction",
            "lambda:DeleteEventSourceMapping",
            "lambda:DeleteFunction",
            "lambda:GetEventSourceMapping",
            "lambda:ListEventSourceMappings",
            "lambda:RemovePermission",
            "lambda:UpdateEventSourceMapping",
            "lambda:UpdateFunctionCode",
            "lambda:UpdateFunctionConfiguration",
            "lambda:GetFunction",
            "lambda:ListFunctions"
          ],
          "Resource" : [
            "*"
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "autoscaling:*"
          ],
          "Resource" : [
            "*"
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "sqs:ReceiveMessage",
            "sqs:SendMessage",
            "sqs:SetQueueAttributes",
            "sqs:PurgeQueue"
          ],
          "Resource" : [
            "*"
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "elasticloadbalancing:AddTags",
            "elasticloadbalancing:AttachLoadBalancerToSubnets",
            "elasticloadbalancing:ConfigureHealthCheck",
            "elasticloadbalancing:DescribeInstanceHealth",
            "elasticloadbalancing:DescribeLoadBalancerAttributes",
            "elasticloadbalancing:DescribeLoadBalancerPolicyTypes",
            "elasticloadbalancing:DescribeLoadBalancerPolicies",
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeTags",
            "elasticloadbalancing:DetachLoadBalancerFromSubnets",
            "elasticloadbalancing:ModifyLoadBalancerAttributes",
            "elasticloadbalancing:RemoveTags"
          ],
          "Resource" : [
            "*"
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "iam:PassRole",
            "iam:GetRole"
          ],
          "Resource" : [
            "*"
          ]
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          "Resource" : "arn:aws:logs:*:*:*"
        },
        {
          "Effect" : "Allow",
          "Action" : ["cloudformation:DescribeStacks"],
          "Resource" : "*"
        },
        {
          "Effect" : "Allow",
          "Action" : [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutDestination",
            "logs:PutDestinationPolicy",
            "logs:PutLogEvents",
            "logs:PutMetricFilter"
          ],
          "Resource" : [
            "*"
          ]
        }
      ]
    }
  )
}

resource "aws_s3_bucket_object" "ps_lamdba" {

  bucket = module.bucket.bucket.id
  key    = "lamda/manage_asg.zip"
  source = "${path.module}/powershell_files/manage_asg.zip"

  etag = filemd5("${path.module}/powershell_files/manage_asg.zip")
}

resource "aws_lambda_function" "ps_lambda" {
  depends_on = [
    aws_s3_bucket_object.ps_lamdba
  ]

  function_name    = "${data.aws_region.current.name}-manage_asg-ps"
  handler          = "manage_asg::manage_asg.Bootstrap::ExecuteFunction"
  s3_bucket        = module.bucket.bucket.id
  s3_key           = aws_s3_bucket_object.ps_lamdba.key
  role             = aws_iam_role.lambda_execution_role.arn
  runtime          = "dotnetcore3.1"
  timeout          = "300"
  memory_size      = "512"
  source_code_hash = filebase64sha256("${path.module}/powershell_files/manage_asg.zip")

  vpc_config {
    security_group_ids = [aws_security_group.lambda-sg.id]
    subnet_ids         = aws_subnet.mgmt[*].id
  }

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.ps_lambda.function_name}"
  retention_in_days = 30

  tags = var.tags
}

resource "aws_sns_topic" "lamda_asg_sns" {
  name = "lamda_asg_sns"
  tags = var.tags
}

resource "aws_sns_topic_subscription" "ps_sns_sub" {
  topic_arn = aws_sns_topic.lamda_asg_sns.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.ps_lambda.arn
}
resource "aws_lambda_permission" "lambda_ps_sns_permission" {
  statement_id  = "lambda_ps_sns_permission"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ps_lambda.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.lamda_asg_sns.arn
}

resource "aws_iam_role" "asg_notifier_role" {
  name = "asg_notifier_role"

  assume_role_policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [{
        "Effect" : "Allow",
        "Principal" : {
          "Service" : ["autoscaling.amazonaws.com"]
        },
        "Action" : ["sts:AssumeRole"]
      }]
    }
  )
}

resource "aws_iam_role_policy" "asg_notifier_role_policy" {
  name = "asg_notifier_rolePolicy"
  role = aws_iam_role.asg_notifier_role.id
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Statement" : [{
        "Effect" : "Allow",
        "Action" : "sns:Publish",
        "Resource" : aws_sns_topic.lamda_asg_sns.arn
        }
      ]
    }

  )
}

resource "aws_autoscaling_lifecycle_hook" "terminate" {
  name                    = "remove_pan_serial"
  autoscaling_group_name  = module.ec2-asg.asg.name
  default_result          = "CONTINUE"
  heartbeat_timeout       = 2000
  lifecycle_transition    = "autoscaling:EC2_INSTANCE_TERMINATING"
  notification_target_arn = aws_sns_topic.lamda_asg_sns.arn
  role_arn                = aws_iam_role.asg_notifier_role.arn

  notification_metadata = jsonencode(
    {
      "panorama_server" : var.panorama-server,
      "tplname" : var.tplname,
      "dgname" : var.dgname
    }
  )
}

resource "aws_autoscaling_lifecycle_hook" "launch" {
  name                    = "add_eni"
  autoscaling_group_name  = module.ec2-asg.asg.name
  default_result          = "ABANDON"
  heartbeat_timeout       = 2000
  lifecycle_transition    = "autoscaling:EC2_INSTANCE_LAUNCHING"
  notification_target_arn = aws_sns_topic.lamda_asg_sns.arn
  role_arn                = aws_iam_role.asg_notifier_role.arn

}