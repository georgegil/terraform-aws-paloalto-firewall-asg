output "nat_elastic_ip" {
  description = "NAT Gateway External IP addresses"
  value       = aws_eip.natgw_eip[*].public_ip
}
