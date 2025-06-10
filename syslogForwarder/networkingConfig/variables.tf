# version 0.2 #

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

variable "approved_ip" {
  default     = "XXX.XXX.XXX.XXX/32"
  description = "Specify approved IP. Utilize source_address_prefixes if you require more than 1 IP"
}
