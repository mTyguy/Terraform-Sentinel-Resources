# version 0.1 #

#deploy Vnet, subnet, NSG, & NSG rules for linux syslogForwarder machine

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

#create resource group

resource "azurerm_resource_group" "Sentinel-RG" {
  name     = var.resource_group_name
  location = var.resource_group_location

  tags = var.resource_tags
}

###

#create virtual network and subnet

resource "azurerm_virtual_network" "syslogForwarder-Net" {
  name                = "syslogForwarder-network"
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name
  address_space       = ["192.168.1.0/24"]
  dns_servers         = ["1.1.1.2"] /* DNS servers of your choice*/

  tags = var.resource_tags
}

resource "azurerm_subnet" "syslogForwarder-subnet" {
  name                 = "syslogForwarder-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.syslogForwarder-Net.name
  address_prefixes     = ["192.168.1.0/24"]
}

###
#create NSG, rules, and association with subnet

resource "azurerm_network_security_group" "syslogForwarder-Nsg" {
  name                = "syslogForwarder-NSG"
  resource_group_name = var.resource_group_name
  location            = var.resource_group_location
}

resource "azurerm_network_security_rule" "syslogForwarder-NgsRule-AllowSSHin" {
  name                        = "Allow-InBound-SSH"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.approved_ip
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.syslogForwarder-Nsg.name
}

resource "azurerm_network_security_rule" "syslogForwarder-NsgRules-Allow514in" {
  name                        = "Allow-InBound-514"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "514"
  source_address_prefix       = var.approved_ip
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.syslogForwarder-Nsg.name
}

resource "azurerm_subnet_network_security_group_association" "syslogForwarder-NsgAssociation" {
  subnet_id                 = azurerm_subnet.syslogForwarder-subnet.id
  network_security_group_id = azurerm_network_security_group.syslogForwarder-Nsg.id
}
