# Terraform Palo Alto Firewall Module


This repository contains TF templates for deploying VM-Series Firewalls in an AWS Automated Scale Group (ASG) behind AWS Gateway Load Balancer.

[VM-Series with AWS Gateway Load Balancer Documentation](https://docs.paloaltonetworks.com/vm-series/10-0/vm-series-deployment/set-up-the-vm-series-firewall-on-aws/vm-series-integration-with-gateway-load-balancer.html)

This is a variation of Palo Alto's https://github.com/PaloAltoNetworks/AWS-GWLB-VMSeries/tree/main/terraform/security_stack, but done properly and using powershell instead of python. 

She ain't perfect, and needs a lot of polishing (not to mention powershell exception handling etc), but this a copy of a module used in a production environment.. 


## Development

Feel free to create a branch and submit a pull request to make changes and improvements to the module.