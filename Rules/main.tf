# version 0.5 #

##########
#change-log
#2025-01-28 created NRT rules
#2025-04-14 mapped entities to alerts. need to review what custom_details actually do, also look at automation rules
#2025-05-18 added data block to remove need for workspace_id variable
#2025-05-19 NRT_NonUs_Logins_v03

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


#NonUS login detection

resource "azurerm_sentinel_alert_rule_nrt" "NRT_NonUs_Logins_v02" {
  name                       = "NonUS_Logins_Watchlist_v02"
  description                = "Rule is intended to trigger off successful NonUS logins. Intentionally excluding countries designated by US Federal Government as Foriengn Adversaries. Disabled in favor of utilizing NRT_NonUs_Logins_v03"
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
      identifier  = "AadUserId"
      column_name = "UserPrincipalName"
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

###

resource "azurerm_sentinel_alert_rule_nrt" "NRT_NonUs_Logins_v03" {
  name                       = "NonUS_Logins_Watchlist_v03"
  description                = "Rule is intended to trigger off successful NonUS logins. Includes a builtin whitelisting mechanism that checks a remove csv file for user travel destination countrys and return dates. Intentionally excluding countries designated by US Federal Government as Foriengn Adversaries"
  log_analytics_workspace_id = data.terraform_remote_state.terraform_output.outputs.sentinel_onboarding_workspace_id
  display_name               = "NonUs_Login_Detected_w/whitelisting"
  severity                   = "Medium"
  query                      = <<QUERY
let UserTravel = externaldata (_Username:string,_UserPrincipalName:string,_Country:string,_ReturnDate:datetime)["https://raw.githubusercontent.com/mTyguy/Terraform-Sentinel-Resources/refs/heads/main/Rules/externaldata/usertravel.csv"]with (format="csv",ignoreFirstRecord=true);
SigninLogs
| join kind=inner UserTravel on $left.UserPrincipalName==$right._UserPrincipalName
| where Status.errorCode in ("0","50140","50055","50057","50155","50105","50133","50005","50076","50079","50173","500158","50072","50074","53003","53000","53001","50129")
| where Location  != "US"
| where (UserPrincipalName == _UserPrincipalName and Location == _Country and TimeGenerated > _ReturnDate)
| where not(RiskState has_any ("confirmedSafe", "remediated", "dismissed", "atRisk", "confirmedCompromised")) //changes in user risk state and generate false positive detections
//exclude foreign adversarial countries for another watchlist to reduce extra alerts
QUERY
  enabled                    = true
  suppression_enabled        = false
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1078"]

  #define entities
  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "AadUserId"
      column_name = "UserPrincipalName"
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

###

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

  #define entities
  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "AadUserId"
      column_name = "UserPrincipalName"
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

###

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
//
let RMMIndicatorUrls =
RMMIndicators | project _Url;
//
DeviceNetworkEvents
| where RemoteUrl has_any (RMMIndicatorUrls)
| where not(RemoteUrl has_any (SanctionedRMMUrls))
QUERY
  enabled                    = true
  suppression_enabled        = false
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219"]

  #define entities
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

################
#Scheduled Rules
#https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sentinel_alert_rule_scheduled







###

#Example
/*
resource "azurerm_sentinel_alert_rule_scheduled" "SCHDexamplerule01" {
  name                       = "SCHDexample01"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "SCHDexample01"
  severity                   = "Medium"
  enabled                    = "false"
  query                      = <<QUERY
Table
  | take 10
QUERY
  query_frequency            = "PT5H"
  query_period               = "PT5H"
  suppression_duration       = "PT5H"
  suppression_enabled        = false
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  incident {
    create_incident_enabled = true
    grouping {
      by_alert_details        = []
      by_custom_details       = []
      by_entities             = []
      enabled                 = false
      entity_matching_method  = "AllEntities"
      lookback_duration       = "PT5M"
      reopen_closed_incidents = false
    }
  }
}
*/
