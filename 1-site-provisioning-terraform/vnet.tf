resource "azurerm_network_security_group" "vnet_security_group" {
  name                = "${azurerm_virtual_network.cvad_vnet.name}-nsg"
  location            = azurerm_resource_group.ctx_resource_group.location
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
}

resource "azurerm_virtual_network" "cvad_vnet" {
  name                = var.cvad_vnet_name
  location            = azurerm_resource_group.ctx_resource_group.location
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
  address_space       = [var.cvad_vnet_address_space]
}

resource "azurerm_subnet" "cvad_subnet" {
  name                 = var.cvad_subnet_name
  resource_group_name  = azurerm_resource_group.ctx_resource_group.name
  virtual_network_name = azurerm_virtual_network.cvad_vnet.name
  address_prefixes     = [var.cvad_vnet_address_prefix]
}

resource "azurerm_subnet_network_security_group_association" "vda_subnet_association" {
  subnet_id                 = azurerm_subnet.cvad_subnet.id
  network_security_group_id = azurerm_network_security_group.vnet_security_group.id
}

resource "azurerm_virtual_network_dns_servers" "cvad_vnet_dns_server" {
  virtual_network_id = azurerm_virtual_network.cvad_vnet.id
  dns_servers        = [azurerm_windows_virtual_machine.adVM.private_ip_address]
}

resource "azurerm_network_security_rule" "license_server_inbound_rules" {
  name                        = "license-server-inbound-rules"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_ranges     = ["7279", "8083", "27000"]
  source_address_prefix       = "*"
  destination_address_prefix  = var.setup_independent_license_server ? azurerm_network_interface.license_server_nic[0].private_ip_address : var.ddc_private_ip_addr
  resource_group_name         = azurerm_resource_group.ctx_resource_group.name
  network_security_group_name = azurerm_network_security_group.vnet_security_group.name
}

resource "azurerm_network_security_rule" "storefront_inbound_rules" {
  name                         = "storefront-inbound-rules"
  priority                     = 101
  direction                    = "Inbound"
  access                       = "Allow"
  protocol                     = "*"
  source_port_range            = "*"
  destination_port_ranges      = ["80", "443"]
  source_address_prefix        = "*"
  destination_address_prefix   = var.storefront_vm_count == 0 ? azurerm_network_interface.ddc_nic.private_ip_address : null
  destination_address_prefixes = var.storefront_vm_count == 0 ? null : azurerm_network_interface.storefront_nic[*].private_ip_address
  resource_group_name          = azurerm_resource_group.ctx_resource_group.name
  network_security_group_name  = azurerm_network_security_group.vnet_security_group.name

  depends_on = [
    azurerm_network_interface.ddc_nic,
    azurerm_network_interface.storefront_nic,
    azurerm_network_security_rule.license_server_inbound_rules
  ]
}

resource "azurerm_network_security_rule" "webstudio_inbound_rules" {
  count                       = var.webstudio_count
  name                        = "webstudio-inbound-rules"
  priority                    = 102
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_ranges     = ["80", "443"]
  source_address_prefix       = "*"
  destination_address_prefix  = var.webstudio_count == 0 ? azurerm_network_interface.ddc_nic.private_ip_address : azurerm_network_interface.webstudio_nic[0].private_ip_address
  resource_group_name         = azurerm_resource_group.ctx_resource_group.name
  network_security_group_name = azurerm_network_security_group.vnet_security_group.name

  depends_on = [
    azurerm_network_interface.ddc_nic,
    azurerm_network_interface.webstudio_nic,
    azurerm_network_security_rule.license_server_inbound_rules
  ]
}

resource "azurerm_network_security_rule" "rdp_inbound_rules" {
  count                       = length(var.vnet_rdp_source_ips) == 0 ? 0 : 1
  name                        = "rdp-inbound-rules"
  priority                    = 103
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["3389"]
  source_address_prefix       = length(var.vnet_rdp_source_ips) == 1 ? var.vnet_rdp_source_ips[0] : null
  source_address_prefixes     = length(var.vnet_rdp_source_ips) > 1 ? var.vnet_rdp_source_ips : null
  destination_address_prefix  = var.cvad_vnet_address_prefix
  resource_group_name         = azurerm_resource_group.ctx_resource_group.name
  network_security_group_name = azurerm_network_security_group.vnet_security_group.name
}
