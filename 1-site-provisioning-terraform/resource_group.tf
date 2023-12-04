resource "azurerm_resource_group" "ctx_resource_group" {
  name     = var.cvad_component_resource_group_name
  location = var.azure_location
}


