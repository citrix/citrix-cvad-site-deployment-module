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

    random = {
      source  = "hashicorp/random"
      version = ">=3.5.1"
    }

    null = {
      source  = "hashicorp/null"
      version = ">=3.2.1"
    }
  }

  backend "local" {
    workspace_dir = "../.terraform/workspace"
    path = "../cvad_deployment.tfstate"
  }
}

