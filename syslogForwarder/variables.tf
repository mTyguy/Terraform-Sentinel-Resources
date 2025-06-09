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
