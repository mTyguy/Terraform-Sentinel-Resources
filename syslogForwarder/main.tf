# version 0.3 #

#deploy public IP, NIC, & Linux VM

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

data "terraform_remote_state" "rg_config" {
  backend = "local"

  config = {
    path = "../enchancedDeployment/deploySentinel/terraform.tfstate"
  }
}

data "terraform_remote_state" "network_config" {
  backend = "local"

  config = {
    path = "../syslogForwarder/networkingConfig/terraform.tfstate"
  }
}

###

#create network interface and public IP

resource "azurerm_network_interface" "syslogForwarder-NIC" {
  name                = "syslogForwarder-NIC"
  location            = data.terraform_remote_state.rg_config.outputs.sentinel_rg_location
  resource_group_name = data.terraform_remote_state.rg_config.outputs.sentinel_rg_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = data.terraform_remote_state.network_config.outputs.syslogForwarder_subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = "192.168.1.6"
    public_ip_address_id          = azurerm_public_ip.syslogForwarder-pubIP.id
  }

  tags = var.resource_tags

}

resource "azurerm_public_ip" "syslogForwarder-pubIP" {
  name                = "syslogForwarder-pubIP"
  resource_group_name = data.terraform_remote_state.rg_config.outputs.sentinel_rg_name
  location            = data.terraform_remote_state.rg_config.outputs.sentinel_rg_location
  allocation_method   = "Static"

  tags = var.resource_tags
}

#create linux VM, disk, work with ssh keys, and run AMA script

resource "azurerm_linux_virtual_machine" "syslogForwarder-VM" {
  admin_username                  = "admin"
  computer_name                   = "syslogForwarder"
  disable_password_authentication = true
  name                            = "syslogForwarder-VM"
  resource_group_name             = data.terraform_remote_state.rg_config.outputs.sentinel_rg_name
  location                        = data.terraform_remote_state.rg_config.outputs.sentinel_rg_location
  size                            = "Standard_B1ms" /* 1vCPU 2gbRam - change per needs*/
  network_interface_ids = [
    azurerm_network_interface.syslogForwarder-NIC.id
  ]

  admin_ssh_key {
    username   = "admin"
    public_key = file("linuxForwarder_id_rsa.pub")
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

  identity {
    type = "SystemAssigned"
  }

  provisioner "remote-exec" {
    connection {
      type        = "ssh"
      user        = "admin"
      private_key = file("/home/admin/.ssh/id_rsa")
      host        = azurerm_public_ip.syslogForwarder-pubIP.ip_address
    }
    inline = [
      "sudo wget -O Forwarder_AMA_installer.py https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/Syslog/Forwarder_AMA_installer.py&&sudo python3 Forwarder_AMA_installer.py"
    ]
  }

  tags = var.resource_tags

}

#create vm extension required for solution

resource "azurerm_virtual_machine_extension" "syslogForwarderAzureMonitorLinuxAgent" {
  name                       = "syslogForwarderAzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.syslogForwarder-VM.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.6"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true

  tags = var.resource_tags

}
