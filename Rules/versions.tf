# version 0.1 #

terraform {
  required_version = "~>1.12"
}

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>4.24"
    }
  }
}
