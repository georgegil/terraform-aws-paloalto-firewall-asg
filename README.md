# Terraform Palo Alto Firewall Module


This repository contains TF templates for deploying VM-Series Firewalls in an AWS Automated Scale Group (ASG) behind AWS Gateway Load Balancer.

```hcl
module "egress-vpc" {
  source = "github.com/georgegil/terraform-aws-paloalto-firewall-asg.git?ref=<current version>"

  tags = {
    "Tag_1" = "Value_1"
    "Tag_2" = "Value_2"
    "Tag_3" = "Value_3"
  }

  pan_version           = "10.0.7"
  vpc_cidr              = "10.182.240.0/24"
  primary_transit_gw_id = "tgw-0b669a02547b4"
  public_key            = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDquCjWN+YBvZeY6yyiZoKJCk0d"
  panorama_server       = "10.20.50.100"
  hostname              = "firewall123"
  pan_template_name     = "CloudPaloMgmt_mig"
  pan_device_group_name = "AWS-FW"
  domain_name           = ["gglabs.co.uk"]
  dns_server            = ["10.100.100.100", "10.200.200.200"]
  instance_type         = "m5.large"
  pan_os_authcode       = "1234568"
  vm-auth-key           = "1234568"
  pan_api_key           = "1234567"
  
  spoke_vpc = {
    us-west-2-dev = {
      transit_gw_id = "tgw-0b669a02b8159a2b4"
      vpc_cidr      = "10.182.144.0/20"
    }
  }

  
}
```

where `<current version>` is the most recent release.


[VM-Series with AWS Gateway Load Balancer Documentation](https://docs.paloaltonetworks.com/vm-series/10-0/vm-series-deployment/set-up-the-vm-series-firewall-on-aws/vm-series-integration-with-gateway-load-balancer.html)

This is a variation of Palo Alto's https://github.com/PaloAltoNetworks/AWS-GWLB-VMSeries/tree/main/terraform/security_stack, but done properly and using powershell instead of python. 

She ain't perfect, and needs a lot of polishing (not to mention powershell exception handling etc), but this a copy of a module used in a production environment.. 


## Development

Feel free to create a branch and submit a pull request to make changes and improvements to the module.