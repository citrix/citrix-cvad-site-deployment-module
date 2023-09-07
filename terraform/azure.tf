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
