# version 0.1 #

variable "resource_tags" {
  description = "define tags for your resources"
  default = {
    enviornment = "SentinelResources"
  }
}

variable "subscription_id" {
  default     = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
  description = "define the Azure subscription's ID"
}

variable "resource_group_location" {
  default     = "East Us"
  description = "define the Azure region resources will reside in"
}

variable "resource_group_name" {
  default     = "Sentinel-RG"
  description = "Name the resource group your Sentinel resources will reside in"
}
