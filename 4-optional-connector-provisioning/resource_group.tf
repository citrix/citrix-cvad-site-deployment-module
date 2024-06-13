# Create an Azure resource group to host the Citrix Cloud Connector VMs
resource "azurerm_resource_group" "ctx_connector_resource_group" {
  name     = var.citrix_cloud_connector_resource_group_name
  location = var.azure_location
}

# If you want to use an existing resource group, uncomment the following block and comment the above block
# data "azurerm_resource_group" "ctx_connector_resource_group" {
#   name = var.citrix_cloud_connector_resource_group_name
# }
