data "azurerm_virtual_network" "cvad_component_vnet" {
  name                = var.cvad_vnet_name
  resource_group_name = var.cvad_component_resource_group_name
}

data "azurerm_virtual_machine" "ddc" {
  name                = var.ddc_machine_name
  resource_group_name = var.cvad_component_resource_group_name
}
