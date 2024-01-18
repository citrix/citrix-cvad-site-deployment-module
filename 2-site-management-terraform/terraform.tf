terraform {
  required_version = ">= 1.1.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">=3.21.0"
    }

    citrix = {
      source  = "citrix/citrix"
      version = "=0.3.3"
    }

    local = {
      source  = "hashicorp/local"
      version = ">=2.4.0"
    }
  }

  backend "local" {
    workspace_dir = "./.terraform/workspace"
    path = "./site_management.tfstate"
  }
}

provider "azurerm" {
  subscription_id = var.azure_subscription_id
  client_id       = var.azure_client_id
  client_secret   = var.azure_client_secret
  tenant_id       = var.azure_tenant_id
  environment     = var.azure_environment
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "citrix" {
  hostname                    = data.azurerm_virtual_machine.ddc.public_ip_address
  client_id                   = "${var.active_directory_domain_name}\\${var.advm_admin_username}"
  client_secret               = var.advm_admin_password
  disable_ssl_verification    = true
}
