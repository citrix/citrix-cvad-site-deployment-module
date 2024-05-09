resource "citrix_azure_hypervisor_resource_pool" "azure_resource_pool" {
  name                           = var.ddc_resource_pool_name
  hypervisor                     = citrix_azure_hypervisor.azure_hypervisor.id
  region                         = var.ddc_resource_pool_region
  virtual_network_resource_group = data.azurerm_virtual_network.cvad_component_vnet.resource_group_name
  virtual_network                = data.azurerm_virtual_network.cvad_component_vnet.name
  subnets                        = data.azurerm_virtual_network.cvad_component_vnet.subnets
}
