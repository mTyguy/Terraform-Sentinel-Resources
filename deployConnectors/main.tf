# version 0.2 #

#deploy connectors

##change log
#

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

##Create connector for Entra Audit Logs
#Entra Audit log activity
#https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-entra-id

resource "azurerm_sentinel_data_connector_azure_active_directory" "terra-sentinel-entra-connector" {
  name                       = "terra-sentinel-entra-connector"
  log_analytics_workspace_id = var.log_analytics_id
  tenant_id                  = var.tenant_id
}

##Create connector for Office365/Exchange Activity
#Ingest Office, Sharepoint, and Teams logs
#https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-365

resource "azurerm_sentinel_data_connector_office_365" "sentinel-connector-office365" {
  name                       = "sentinel-connector-office365"
  log_analytics_workspace_id = var.log_analytics_id
}

##Create connector for Microsoft Defender -- Requires high level licensing
#This product used to be called "Microsoft Threat Protection" and connector name hasn't been changed to reflect
#https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-defender-xdr

resource "azurerm_sentinel_data_connector_microsoft_threat_protection" "sentinel-connector-defender" {
  name                       = "sentinel-connector-defender"
  log_analytics_workspace_id = var.log_analytics_id
}

##Create connector for Defender for Office 365
#This product used to be called "Office 365 ATP" and connector name hasn't been changed to reflect
#https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-defender-for-office-365

resource "azurerm_sentinel_data_connector_office_atp" "defenderforO365" {
  name                       = "sentinel-connector-defenderforO365"
  log_analytics_workspace_id = var.log_analytics_id
}

##Create connector for Microsoft Defender for Endpoint - needs to be done manually, see below
#https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender?tabs=MDE#connect-to-microsoft-defender-xdr
#This product used to be called "Microsoft Defender ATP" and connector name hasn't been changed to reflect
#https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-defender-xdr

resource "azurerm_sentinel_data_connector_microsoft_defender_advanced_threat_protection" "sentinel-connector-mde" {
  name                       = "sentinel-connector-mde"
  log_analytics_workspace_id = var.log_analytics_id
}

##Create connector for Microsoft Defender for Cloud Apps, see the below first
#https://learn.microsoft.com/en-us/defender-cloud-apps/siem-sentinel#integrating-with-microsoft-sentinel
#This product used to be called "Microsoft Cloud App Security" and connector name hasn't been changed to reflect
#https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-defender-for-cloud-apps

resource "azurerm_sentinel_data_connector_microsoft_cloud_app_security" "sentinel-connector-cloudapps" {
  name                       = "sentinel-connector-cloudapps"
  log_analytics_workspace_id = var.log_analytics_id
}

##Create connector for Microsoft Defender for Identity
#This product used to be called "Azure Advanced Threat Protection" and connector name hasn't been changed to reflect
#https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-defender-for-identity

resource "azurerm_sentinel_data_connector_azure_advanced_threat_protection" "sentinel-connector-defenderforidentity" {
  name                       = "sentinel-connector-defenderforidentity"
  log_analytics_workspace_id = var.log_analytics_id
}

##Create connector for Microsoft Threat Intelligence
#content hub Threat Intel might be better, plus it adds some Analytics Rules
#https://learn.microsoft.com/en-us/azure/sentinel/data-connectors/microsoft-defender-threat-intelligence

resource "azurerm_sentinel_data_connector_microsoft_threat_intelligence" "sentinel-connector-MSthreatintel" {
  name                                         = "sentinel-connector-MSthreatintel"
  log_analytics_workspace_id                   = var.log_analytics_id
  microsoft_emerging_threat_feed_lookback_date = "2025-05-01T00:00:00Z"

  #Max lookback date below
  #  microsoft_emerging_threat_feed_lookback_date = "1970-01-01T00:00:00Z"
}

##Documentation
#Microsoft Connectors permissions and licensing documentation
#https://learn.microsoft.com/en-us/azure/sentinel/connect-services-api-based
