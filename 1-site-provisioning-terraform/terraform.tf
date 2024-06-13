terraform {
  required_version = ">= 1.1.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">=3.21.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = ">=2.3.0"
    }

    local = {
      source  = "hashicorp/local"
      version = ">=2.4.0"
    }

    random = {
      source  = "hashicorp/random"
      version = ">=3.5.1"
    }
  }

  backend "local" {
    workspace_dir = "./.terraform/workspace"
    path = "./cvad_deployment.tfstate"
  }
}

provider "azurerm" {
  subscription_id = var.azure_subscription_id
  client_id       = var.azure_client_id
  client_secret   = var.azure_client_secret
  tenant_id       = var.azure_tenant_id
  environment     = var.azure_environment

  partner_id = "2b3681fa-6d91-4bcf-888c-7eebdf549d48"
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}
