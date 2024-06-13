data "azurerm_resource_group" "active_directory_resource_group" {
  name     = var.active_directory_resource_group_name
}

data "azurerm_subnet" "active_directory_subnet" {
  name                 = var.active_directory_subnet_name
  virtual_network_name = var.active_directory_vnet_name
  resource_group_name  = data.azurerm_resource_group.active_directory_resource_group.name
}

data "azurerm_network_security_group" "active_directory_nsg" {
  name                = var.active_directory_security_group_name
  resource_group_name = data.azurerm_resource_group.active_directory_resource_group.name
}
