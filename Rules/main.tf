# version 0.5 #

##########
#change-log
#2025-01-28 created NRT rules
#2025-04-14 mapped entities to alerts
#2025-05-18 added data block to remove need for workspace_id variable
#2025-05-19 NRT_NonUs_Logins_v03
#2025-06-02 removed user travel rule, which had issues. created NRT_NonUs_Logins_Whitelisting_v02. fixed some entities mapping.

###

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

data "terraform_remote_state" "terraform_output" {
  backend = "local"

  config = {
    path = "../enchancedDeployment/deploySentinel/terraform.tfstate"
  }
}

#########################################################################################################
#NearRealTime (NRT) Rules
#these rules are meant for your most urgent detections
#they are designed to trigger as near to the event time as possible
#you can only have 50 NRT rules as of writing
#https://learn.microsoft.com/en-us/azure/sentinel/near-real-time-rules
#https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sentinel_alert_rule_nrt

###
#User Login related detections

resource "azurerm_sentinel_alert_rule_nrt" "NRT_NonUs_Logins_v02" {
  name                       = "NonUS_Logins_Watchlist_v02"
  description                = "Rule is intended to trigger off successful NonUS logins. Intentionally excluding countries designated by US Federal Government as Foriengn Adversaries. Disabled in favor of utilizing NRT_NonUs_Logins_Whitelisting_v02"
  log_analytics_workspace_id = data.terraform_remote_state.terraform_output.outputs.sentinel_onboarding_workspace_id
  display_name               = "NonUs_Login_Detected"
  severity                   = "Medium"
  query                      = <<QUERY
SigninLogs
| where Status.errorCode in ("0","50140","50055","50057","50155","50105","50133","50005","50076","50079","50173","500158","50072","50074","53003","53000","53001","50129")
| where LocationDetails.countryOrRegion !in ("US")
| where LocationDetails.countryOrRegion !in ("CN","HK","CU","IR","KP","VE")
//exclude foreign adversarial countries for another watchlist to reduce extra alerts
QUERY
  enabled                    = false
  suppression_enabled        = false
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1078"]

  #define entities
  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "Identity"
    }
  }
  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IPAddress"
    }
  }

  #define custom entities
  custom_details = {
    Location         = "Location"
    RiskDuringSignIn = "RiskLevelDuringSignIn"
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  incident {
    create_incident_enabled = true

    grouping {
      by_alert_details        = []
      by_custom_details       = []
      by_entities             = []
      enabled                 = true
      entity_matching_method  = "AllEntities"
      lookback_duration       = "PT5M"
      reopen_closed_incidents = false
    }
  }
}

#

#NonUs login detection with Whitelisting mechanism based on users' properties as described in their respective Entra Properties

resource "azurerm_sentinel_alert_rule_nrt" "NRT_NonUs_Logins_Whitelisting_v02" {
  name                       = "NonUS_Logins_Watchlist_with_Whitelisting_v02"
  description                = "Rule is intended to trigger off successful NonUS logins. Includes a builtin whitelisting mechanism that checks a remote csv file pulled from Entra properties that checks what Countries user is expected to login from. Intentionally excluding countries designated by US Federal Government as Foriengn Adversaries"
  log_analytics_workspace_id = data.terraform_remote_state.terraform_output.outputs.sentinel_onboarding_workspace_id
  display_name               = "NonUs_Login_Detected_with_Whitelisting_v02"
  severity                   = "Medium"
  query                      = <<QUERY
let UserData = externaldata(_accountEnabled:string, _displayName:string, _userPrincipalName:string, _id:string, _country:string, _usageLocation:string, _userType:string)
    ["https://raw.githubusercontent.com/mTyguy/Terraform-Sentinel-Resources/refs/heads/main/Rules/externaldata/users.csv"]
    with (format="csv",ignoreFirstRecord=true);
SigninLogs
| join kind=rightouter UserData on $left.UserId==$right._id
| where Status.errorCode in ("0","50140","50055","50057","50155","50105","50133","50005","50076","50079","50173","500158","50072","50074","53003","53000","53001","50129")
| where LocationDetails.countryOrRegion !in ("US")
| where LocationDetails.countryOrRegion !in ("CN","HK","CU","IR","KP","VE")
| where not(_country contains Location)
//exclude foreign adversarial countries for another watchlist to reduce extra alerts
QUERY
  enabled                    = true
  suppression_enabled        = false
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1078"]

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "Identity"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "UserId"
    }
  }
  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IPAddress"
    }
  }

  custom_details = {
    Location         = "Location"
    RiskDuringSignIn = "RiskLevelDuringSignIn"
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  incident {
    create_incident_enabled = true

    grouping {
      by_alert_details        = []
      by_custom_details       = []
      by_entities             = []
      enabled                 = true
      entity_matching_method  = "AllEntities"
      lookback_duration       = "PT5M"
      reopen_closed_incidents = false
    }
  }
}

#

#Logins from nations defined as US Foreign Adversaries (FA)
resource "azurerm_sentinel_alert_rule_nrt" "NRT_FA_Logins_Watchlist_v02" {
  name                       = "FA_Logins_Watchlist_v02"
  description                = "Rule intended to trigger off successful logins from countries designated as Foriegn Adversaries by US Federal Government"
  log_analytics_workspace_id = data.terraform_remote_state.terraform_output.outputs.sentinel_onboarding_workspace_id
  display_name               = "Foreign_Adversarial_Login_Detected"
  severity                   = "High"
  query                      = <<QUERY
SigninLogs
| where Status.errorCode in ("0","50140","50055","50057","50155","50105","50133","50005","50076","50079","50173","500158","50072","50074","53003","53000","53001","50129")
| where LocationDetails.countryOrRegion in ("CN","HK","CU","IR","KP","VE")
QUERY
  enabled                    = true
  suppression_enabled        = false
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1078"]

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "Identity"
    }
  }
  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "IPAddress"
    }
  }

  custom_details = {
    Location         = "Location"
    RiskDuringSignIn = "RiskLevelDuringSignIn"
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  incident {
    create_incident_enabled = true

    grouping {
      by_alert_details        = []
      by_custom_details       = []
      by_entities             = []
      enabled                 = true
      entity_matching_method  = "AllEntities"
      lookback_duration       = "PT5M"
      reopen_closed_incidents = false
    }
  }
}

###
#User post compromise detection rules

resource "azurerm_sentinel_alert_rule_scheduled" "SCH_Risky_User_Registers_New_MFA_v01" {
  name                       = "Risky_User_Registers_New_MFA_v01"
  description                = "Rule to detect when a user with an active risk state registers a new MFA method."
  log_analytics_workspace_id = data.terraform_remote_state.terraform_output.outputs.sentinel_onboarding_workspace_id
  display_name               = "Risky_User_Registers_New_MFA_v01"
  severity                   = "High"
  query                      = <<QUERY
let AtRiskUsers =
AADRiskyUsers
| where not(RiskState has_any ("none", "confirmedSafe", "dismissed"))
| distinct UserPrincipalName;
AuditLogs
| where OperationName == "User registered security info"
| mv-expand TargetResources.[0].userPrincipalName to typeof(string)
| extend _userWithNewMFA = TargetResources_0_userPrincipalName
| where isnotnull(_userWithNewMFA)
| where _userWithNewMFA has_any(AtRiskUsers)
QUERY
  enabled                    = true
  suppression_enabled        = false
  tactics                    = ["Persistence"]
  techniques                 = ["T1098"]
  query_frequency            = "PT30M"
  query_period               = "PT30M"

/*
need to flush out entity mapping
   entity_mapping {
     entity_type = "Account"
     field_mapping {
       identifier  = "Name"
       column_name = "InitiatingProcessAccountSid"
     }
   }
*/
  event_grouping {
    aggregation_method = "SingleAlert"
  }

  incident {
    create_incident_enabled = true

    grouping {
      by_alert_details        = []
      by_custom_details       = []
      by_entities             = []
      enabled                 = true
      entity_matching_method  = "AllEntities"
      lookback_duration       = "PT5M"
      reopen_closed_incidents = false
    }
  }
}

###
#Application/Service Principal Related rules

resource "azurerm_sentinel_alert_rule_nrt" "NRT_Application_Registered_RedirectUri_LocalHost_Authentication_v01" {
  name                       = "Application__Registered_RedirectUri_LocalHost_Authentication_v01"
  description                = "Rule to detect when an application is registered with a RedirectUri set to localhost or loopback address. See https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app"
  log_analytics_workspace_id = data.terraform_remote_state.terraform_output.outputs.sentinel_onboarding_workspace_id
  display_name               = "Application_Registered_RedirectUri_LocalHost_Authentication_v01"
  severity                   = "High"
  query                      = <<QUERY
AuditLogs
| where OperationName in ("Add application", "Add service principal")
| mv-expand (TargetResources)
| where (TargetResources.modifiedProperties.[0].displayName == "AppAddress" or TargetResources.modifiedProperties.[1].displayName == "AppAddress")
| where (TargetResources.modifiedProperties.[0].newValue has_any ("127.0.0.1", "localhost") or TargetResources.modifiedProperties.[1].newValue has_any ("127.0.0.1", "localhost"))
| extend _changedByUpn = InitiatedBy.user.userPrincipalName| extend _changedByUserGuid = InitiatedBy.user.id| extend _changedBySourceIp = InitiatedBy.user.ipAddress
| extend _appName = TargetResources.displayName//| extend _changeOperation = TargetResources.modifiedProperties.[1].displayName| extend _newValue = TargetResources.modifiedProperties.[1].newValue
QUERY
  enabled                    = true
  suppression_enabled        = false
  tactics                    = ["Persistence"]
  techniques                 = ["T1098"]

#need to flush out entity mapping
  #  entity_mapping {
  #    entity_type = "Account"
  #    field_mapping {
  #      identifier  = "Name"
  #      column_name = "InitiatingProcessAccountSid"
  #    }
  #  }
  event_grouping {
    aggregation_method = "SingleAlert"
  }

  incident {
    create_incident_enabled = true

    grouping {
      by_alert_details        = []
      by_custom_details       = []
      by_entities             = []
      enabled                 = true
      entity_matching_method  = "AllEntities"
      lookback_duration       = "PT5M"
      reopen_closed_incidents = false
    }
  }
}

#

resource "azurerm_sentinel_alert_rule_nrt" "NRT_Application_RedirectUri_LocalHost_Authentication_Added_v01" {
  name                       = "Application_RedirectUri_LocalHost_Authentication_Added_v01"
  description                = "Rule to detect when a registered application is given a Redirect Url for localhost or loopback address. See https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app"
  log_analytics_workspace_id = data.terraform_remote_state.terraform_output.outputs.sentinel_onboarding_workspace_id
  display_name               = "Application_RedirectUri_LocalHost_Authentication_Added_v01"
  severity                   = "High"
  query                      = <<QUERY
AuditLogs
| where OperationName in ("Update application", "Update service principal")
| mv-expand (TargetResources)
| where TargetResources.modifiedProperties.[0].displayName == "AppAddress"
| where TargetResources.modifiedProperties.[0].newValue has_any ("127.0.0.1", "localhost")
| extend _changedByUpn = InitiatedBy.user.userPrincipalName| extend _changedByUserGuid = InitiatedBy.user.id| extend _changedBySourceIp = InitiatedBy.user.ipAddress
| extend _appName = TargetResources.displayName| extend _changeOperation = TargetResources.modifiedProperties.[0].displayName| extend _newValue = TargetResources.modifiedProperties.[0].newValue
QUERY
  enabled                    = true
  suppression_enabled        = false
  tactics                    = ["Persistence"]
  techniques                 = ["T1098"]

#need to flush out entity mapping
  #  entity_mapping {
  #    entity_type = "Account"
  #    field_mapping {
  #      identifier  = "Name"
  #      column_name = "InitiatingProcessAccountSid"
  #    }
  #  }
  event_grouping {
    aggregation_method = "SingleAlert"
  }

  incident {
    create_incident_enabled = true

    grouping {
      by_alert_details        = []
      by_custom_details       = []
      by_entities             = []
      enabled                 = true
      entity_matching_method  = "AllEntities"
      lookback_duration       = "PT5M"
      reopen_closed_incidents = false
    }
  }
}

###
#Device Related Rules

resource "azurerm_sentinel_alert_rule_nrt" "NRT_Unapproved_RMM_Tools_v01" {
  name                       = "Unapproved_RMM_Tools_v01"
  description                = "Rule is intended to trigger off the detection of unapproved RMM tools via a url connection."
  log_analytics_workspace_id = data.terraform_remote_state.terraform_output.outputs.sentinel_onboarding_workspace_id
  display_name               = "Unapproved_RMM_Tool_Detected"
  severity                   = "Medium"
  query                      = <<QUERY
//get Approved RMM tool Urls from csv file and make them usable
let SanctionedRMM = externaldata(_Url: string, _RmmTool: string)
    ['https://raw.githubusercontent.com/mTyguy/Terraform-Sentinel-Resources/refs/heads/main/Rules/externaldata/ApprovedRmmToolsAndUrls.csv']
    with(format="csv", ignoreFirstRecord=true);
let SanctionedRMMUrls =
SanctionedRMM | project _Url;
//get list of RMM tool Urls from csv file and make them usable
//list is a slight modification from this source https://github.com/jischell-msft/RemoteManagementMonitoringTools/blob/main/Network%20Indicators/RMM_SummaryNetworkURI.csv
let RMMIndicators = externaldata(_Url: string, _RmmTool: string)
    ['https://raw.githubusercontent.com/mTyguy/Terraform-Sentinel-Resources/refs/heads/main/Rules/externaldata/RmmUrlIndicators.csv']
    with(format="csv", ignoreFirstRecord=true);
let RMMIndicatorUrls =
RMMIndicators | project _Url;
DeviceNetworkEvents
| where RemoteUrl has_any (RMMIndicatorUrls)
| where not(RemoteUrl has_any (SanctionedRMMUrls))
QUERY
  enabled                    = true
  suppression_enabled        = false
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219"]

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
  }

  entity_mapping {
    entity_type = "URL"
    field_mapping {
      identifier  = "Url"
      column_name = "RemoteUrl"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessVersionInfoOriginalFileName"
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  incident {
    create_incident_enabled = true

    grouping {
      by_alert_details        = []
      by_custom_details       = []
      by_entities             = []
      enabled                 = true
      entity_matching_method  = "AllEntities"
      lookback_duration       = "PT5M"
      reopen_closed_incidents = false
    }
  }
}
