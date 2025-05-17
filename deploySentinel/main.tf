# version 0.1 #

#deploy resource group, log analytics workspace for Sentinel, & Sentinel itself

#change-log
#

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

#Create resource group
resource "azurerm_resource_group" "terra-sentinel" {
  name     = var.resource_group_name
  location = var.resource_location

  tags = var.resource_tags
}

#Create Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "terra-sentinel-workspace" {
  name                = var.log_analytics_name
  location            = var.resource_location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_analytics_retention

  tags = var.resource_tags
}

#Create Sentinel instance
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "terra-sentinel-onboarding" {
  workspace_id                 = azurerm_log_analytics_workspace.terra-sentinel-workspace.id
  customer_managed_key_enabled = false
}
