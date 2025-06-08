# version 0.1 #

#deploy public IP, NIC, & Linux VM

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

data "terraform_remote_state" "terraform_output" {
  backend = "local"

  config = {
    path = "../syslogForwarder/networkingConfig/terraform.tfstate"
  }
}

#substantiate resource group

resource "azurerm_resource_group" "Sentinel-RG" {
  name     = var.resource_group_name
  location = var.resource_group_location

  tags = var.resource_tags
}

###

#create network interface and public IP

resource "azurerm_network_interface" "syslogForwarder-NIC" {
  name                = "syslogForwarder-NIC"
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = data.terraform_remote_state.terraform_output.outputs.syslogForwarder_subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = "192.168.1.6"
    public_ip_address_id          = azurerm_public_ip.syslogForwarder-pubIP.id
  }

  tags = var.resource_tags

}

resource "azurerm_public_ip" "syslogForwarder-pubIP" {
  name                = "syslogForwarder-pubIP"
  resource_group_name = var.resource_group_name
  location            = var.resource_group_location
  allocation_method   = "Static"

  tags = var.resource_tags
}


#create linux VM, disk, ssh keys

resource "azurerm_linux_virtual_machine" "syslogForwarder-VM" {
  admin_username                  = "admin"
  computer_name                   = "syslogForwarder"
  disable_password_authentication = true
  name                            = "syslogForwarder-VM"
  resource_group_name             = var.resource_group_name
  location                        = var.resource_group_location
  size                            = "Standard_B1ms" /* 1vCPU 2gbRam - change per needs*/
  network_interface_ids = [
    azurerm_network_interface.syslogForwarder-NIC.id
  ]

  admin_ssh_key {
    username   = "admin"
    public_key = file("publickey_id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  tags = var.resource_tags

}
