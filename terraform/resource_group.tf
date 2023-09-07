resource "azurerm_resource_group" "ctx_resource_group" {
  name     = "${var.resource_prefix}-resource-group"
  location = var.azure_location
}

resource "azurerm_resource_group" "machines_resource_group" {
  count = var.vda_machine_count == 0 ? 0 : 1

  name     = "${var.resource_prefix}-vda-resource-group"
  location = var.azure_location
}
