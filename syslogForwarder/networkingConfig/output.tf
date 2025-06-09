# version 0.2 #

output "syslogForwarder_rg_name" {
  value = azurerm_resource_group.syslogForwarder.name
}

output "syslogForwarder_rg_location" {
  value = azurerm_resource_group.syslogForwarder.location
}

output "syslogForwarder_subnet_id" {
  value = azurerm_subnet.syslogForwarder-subnet.id
}
