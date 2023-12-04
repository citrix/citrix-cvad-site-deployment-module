resource "azurerm_public_ip" "ad_public_ip" {
  name                = "${var.advm_machine_name}-pip"
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
  location            = azurerm_resource_group.ctx_resource_group.location
  allocation_method   = "Static"
  domain_name_label   = var.advm_public_ip_dns_prefix
}

resource "azurerm_network_interface" "adVM_nic" {
  name                = "${var.advm_machine_name}-nic"
  location            = azurerm_resource_group.ctx_resource_group.location
  resource_group_name = azurerm_resource_group.ctx_resource_group.name

  ip_configuration {
    name                          = var.ad_ip_config_name
    subnet_id                     = azurerm_subnet.cvad_subnet.id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.ad_private_ip_addr
    public_ip_address_id          = azurerm_public_ip.ad_public_ip.id
  }

  depends_on = [
    azurerm_public_ip.ad_public_ip
  ]
}

resource "azurerm_network_interface_security_group_association" "advm_nsg" {
  network_interface_id      = azurerm_network_interface.adVM_nic.id
  network_security_group_id = azurerm_network_security_group.vnet_security_group.id
}

resource "azurerm_windows_virtual_machine" "adVM" {
  name                = var.advm_machine_name
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
  location            = azurerm_resource_group.ctx_resource_group.location
  size                = var.ctx_vm_size
  admin_username      = var.advm_admin_username
  admin_password      = local.advm_admin_password
  network_interface_ids = [
    azurerm_network_interface.adVM_nic.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2019-Datacenter-gensecond"
    version   = "latest"
  }

  allow_extension_operations = true
  extensions_time_budget     = "PT2H"
}

resource "azurerm_virtual_machine_extension" "advm_dsc" {
  name                 = "${azurerm_windows_virtual_machine.adVM.name}-setup"
  virtual_machine_id   = azurerm_windows_virtual_machine.adVM.id
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"

  settings = <<SETTINGS
    {
      "configuration": {
        "function": "New-ADDCSetup",
        "script": "New-ADDCSetup.ps1",
        "url": "${azurerm_storage_blob.domain_controller_setup_script_zip.url}"
      },
      "configurationArguments": ${jsonencode({
        "AdDomainFQDN"      = "${var.active_directory_domain_name}",
        "ADDomainUsername"  = "${var.advm_admin_username}",
        "UserGroupName"     = "${var.ad_usergroup_name}",
        "OUName"            = "${var.ad_ou_name}",
        "CitrixModulesPath" = "${var.citrix_modules_path}",
        "CASetupScriptUrl"  = "${azurerm_storage_blob.install_ad_cert_authority_script.url}",
        "CACommonName"      = "${local.cert_authority_common_name}"
      })},
      "configurationData": {
        "url": "${azurerm_storage_blob.dsc_configuration_script_data.url}"
      }
    }
  SETTINGS

  protected_settings = <<PROTECTED_SETTINGS
    {
      "configurationArguments": {
        "AdDomainAdminPassword": "${local.advm_admin_password}",
        "AdDefaultUserPassword": "${local.ad_default_user_password}"
      }
    }
  PROTECTED_SETTINGS

  depends_on = [
    azurerm_network_security_rule.rdp_inbound_rules
  ]
}
