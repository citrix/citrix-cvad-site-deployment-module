resource "azurerm_resource_group" "machines_resource_group" {
  name     = var.vda_resource_group_name
  location = var.azure_location
}
