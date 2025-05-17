# version 0.2 #

variable "resource_tags" {
  default = {
    enviornment = "SentinelDeployment-terraform"
    description = "define tags for your resources"
  }
}

variable "subscription_id" {
  default     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  description = "define the Azure subscription's ID"
}

variable "resource_location" {
  default     = "East Us"
  description = "define the Azure region resources will reside in"
}

variable "resource_group_name" {
  default     = "Sentinel-ResourceGroup"
  description = "Name the resource group your Sentinel resources will reside in"
}

variable "log_analytics_name" {
  default     = "Sentinel-LogAnalytics"
  description = "Name the LogAnalytics resource that Sentinel will reside in"
}

variable "log_analytics_retention" {
  default     = "30"
  description = "define how long you wish to retain logs"
}
