# version 0.2 #

output "sentinel_onboarding_workspace_id" {
  value = azurerm_sentinel_log_analytics_workspace_onboarding.terra-sentinel-onboarding.workspace_id
}

output "sentinel_rg_name" {
  value = azurerm_resource_group.terra-sentinel.name
}

output "sentinel_rg_location" {
  value = azurerm_resource_group.terra-sentinel.location
}
