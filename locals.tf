locals {
  region_code = upper(split("-", data.aws_availability_zones.available.zone_ids[0])[0])
  environment = upper(var.tags.Environment)

  dhcp_environment = "TRANSIT-${local.environment}${local.region_code}-dhcp-options"
  dns_sg_name      = "TRANSIT-Route53-DNSRouting-${local.region_code}-${local.environment}"

  # subnet calculation
  vpc_cidr_bit = tonumber(split("/", var.vpc_cidr)[1])

  timezone = {
    "us-west-2"      = "US/Pacific"
    "us-east-1"      = "US/Eastern"
    "eu-west-2"      = "Europe/London"
    "eu-central-1"   = "Europe/Berlin"
    "ap-northeast-1" = "Asia/Tokyo"
    "ap-southeast-1" = "Asia/Singapore"
    "ap-southeast-2" = "Australia/Sydney"

  }


}
