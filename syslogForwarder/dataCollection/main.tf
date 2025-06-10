# version 0.1 #

#deploy data collection rule and association

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

data "terraform_remote_state" "rg_config" {
  backend = "local"

  config = {
    path = "../../enchancedDeployment/deploySentinel/terraform.tfstate"
  }
}

data "terraform_remote_state" "vm_config" {
  backend = "local"

  config = {
    path = "../terraform.tfstate"
  }
}

###

#create data collection rule

resource "azurerm_monitor_data_collection_rule" "syslogForwarderDCR" {
  name                = "syslogForwarderDCR"
  resource_group_name = data.terraform_remote_state.rg_config.outputs.sentinel_rg_name
  location            = var.resource_location
  kind                = "Linux"

  destinations {
    log_analytics {
      workspace_resource_id = data.terraform_remote_state.rg_config.outputs.sentinel_onboarding_workspace_id
      name                  = "Sentinel-LogAnalytics-Wksp"
    }
  }

#the below will get almost all logs, tune as you need to reduce costs
  data_flow {
    streams            = ["Microsoft-Syslog"]
    destinations       = ["Sentinel-LogAnalytics-Wksp"]
    output_stream      = "Microsoft-Syslog"
    transform_kql      = "source"
    built_in_transform = null
  }

#the below will get almost all logs, tune as you need to reduce costs
  data_sources {
    syslog {
      facility_names = ["*"]
      log_levels     = ["*"]
      name           = "syslogForwarderSyslogParameters"
      streams        = ["Microsoft-Syslog"]
    }
  }

  tags = var.resource_tags

}

#create data collection rule association

resource "azurerm_monitor_data_collection_rule_association" "syslogForwarderDCRAssociation" {
  name                    = "syslogForwarderDCRAssociation"
  target_resource_id      = data.terraform_remote_state.vm_config.outputs.syslogForwarder-VM_id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.syslogForwarderDCR.id
}
