# version 0.2 #

variable "subscription_id" {
  default     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  description = "define the Azure subscription ID"
}

variable "log_analytics_id" {
  default     = "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxxx/providers/Microsoft.OperationalInsights/workspaces/xxxxxxx"
  description = "Define the LogAnalytics ID that Sentinel resides in"
}

variable "tenant_id" {
  default     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  description = "define the Entra tenant's ID"
}
