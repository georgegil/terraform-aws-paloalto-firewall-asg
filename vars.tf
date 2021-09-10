
# ---------------------------------------------------------------------------------------------------------------------
# MANDATORY PARAMETERS
# ---------------------------------------------------------------------------------------------------------------------

variable "availability_zones" {
  description = "Availability zones in a region to deploy instances on"
  type        = list(any)
}

variable "vpc_cidr" {
  description = "IP CIDR range for the Security VPC"
  type        = string
}

variable "domain_name" {
  description = "List of private DNS domains that needs to be resolved from within the VPC. First domain in the list is also the DNS search suffix of the VPC."
  type        = list(string)
}

variable "dns_server" {
  description = "DNS servers of the VPC."
  type        = list(string)
}

variable "primary_transit_gw_id" {
  description = "Transit gateway ID"
  type        = string
}

variable "spoke_vpc" {
  description = "CIDR values for the spoke VPC which is using the security VPC as a egress transit"
  type = map(object({
    transit_gw_id = string
    vpc_cidr      = string
  }))
}

variable "public_key" {
  description = "Public key string for AWS SSH Key Pair"
  type        = string
}


variable "tags" {
  description = "Please reference the current tagging policy for required tags and allowed values.  See README for link to policy."
  type        = map(string)
}

variable "pan_api_key" {
  description = "API key for managing insance in panorama"
  type        = string
}

variable "vpc_prefix" {
  description = "The VPC name prefix when creating a non standard VPC"
  type        = string
  default     = null
}

variable "prefix" {
  description = "Deployment ID Prefix"
  type        = string
  default     = "PANW"
}

variable "user_data" {
  description = "User Data for VM Series Bootstrapping. Ex. 'type=dhcp-client\nhostname=PANW\nvm-auth-key=0000000000\npanorama-server=<Panorama Server IP>\ntplname=<Panorama Template Stack Name>\ndgname=<Panorama Device Group Name>' or 'vmseries-bootstrap-aws-s3bucket=<s3-bootstrap-bucket-name>'"
  type        = string
  default     = ""
}

variable "bootstrap_directories" {
  description = "The directories comprising the bootstrap package"
  default = [
    "config/",
    "content/",
    "software/",
    "license/",
    "plugins/"
  ]
}

variable "pan_version" {
  description = "Version of Palo Alto software firewall"
  type        = string
}


variable "instance_type" {
  description = "Instance type of the web server instances in ASG"
  type        = string
  default     = "m3.xlarge"
}

variable "amazon_side_asn_tgw" {
  description = "Private Autonomous System Number (ASN) for the Amazon side of a BGP session. The range is '64512' to '65534' for 16-bit ASNs and '4200000000' to '4294967294' for 32-bit ASNs. Required when creating a Transit Gateway by not specyfying a value for 'tgw_id'."
  type        = number
  default     = null
}

variable "hostname" {
  default     = ""
  description = "The hostname of the VM-series instance"
  type        = string
}

variable "panorama-server" {
  default     = ""
  description = "The FQDN or IP address of the primary Panorama server"
  type        = string
}

variable "panorama-server2" {
  default     = ""
  description = "The FQDN or IP address of the secondary Panorama server"
  type        = string
}

variable "tplname" {
  default     = ""
  description = "The Panorama template stack name"
  type        = string
}

variable "dgname" {
  default     = ""
  description = "The Panorama device group name"
  type        = string
}

variable "dns-primary" {
  default     = ""
  description = "The IP address of the primary DNS server"
  type        = string
}

variable "dns-secondary" {
  default     = ""
  description = "The IP address of the secondary DNS server"
  type        = string
}

variable "vm-auth-key" {
  default     = ""
  description = "Virtual machine authentication key"
  type        = string
}

variable "pan_os_authcode" {
  description = "Palo Alto OS licensing Auth code"
  type        = string
}

variable "op-command-modes" {
  default     = ""
  description = "Set jumbo-frame and/or mgmt-interface-swap"
  type        = string
}
