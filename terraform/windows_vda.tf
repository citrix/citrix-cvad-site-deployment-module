resource "azurerm_network_interface" "windows_vda_nic" {
  count = var.vda_machine_count

  name                = "${var.vda_machine_name}${count.index + 1}-nic"
  location            = azurerm_resource_group.machines_resource_group[0].location
  resource_group_name = azurerm_resource_group.machines_resource_group[0].name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.adVM_subnet.id
    private_ip_address_allocation = "Dynamic"
  }

  depends_on = [
    azurerm_network_interface.adVM_nic,
    azurerm_network_interface.ddc_nic,
    azurerm_network_interface.mssql_vm_nic,
    azurerm_network_interface.storefront_nic,
    azurerm_network_interface.webstudio_nic,
    azurerm_network_interface.director_nic
  ]
}

resource "azurerm_network_interface_security_group_association" "windows_vda_nsg_association" {
  count = var.vda_machine_count

  network_interface_id      = azurerm_network_interface.windows_vda_nic[count.index].id
  network_security_group_id = azurerm_network_security_group.vnet_security_group.id
}

resource "azurerm_managed_disk" "windows_vda_osdisk" {
  count = var.vda_machine_count

  name                 = "${var.vda_machine_name}${count.index + 1}-osdisk"
  location             = azurerm_resource_group.machines_resource_group[0].location
  resource_group_name  = azurerm_resource_group.machines_resource_group[0].name
  storage_account_type = "Standard_LRS"
  create_option        = "Import"
  storage_account_id   = azurerm_storage_account.setup_storage.id
  source_uri           = azurerm_storage_blob.vda_image[0].url
  disk_size_gb         = "128"

  os_type            = "Windows"
  hyper_v_generation = local.hyper_v_generation

  depends_on = [azurerm_storage_blob.vda_image]
}

resource "azurerm_virtual_machine" "vda" {
  count = var.vda_machine_count

  name                = "${var.vda_machine_name}${count.index + 1}"
  resource_group_name = azurerm_resource_group.machines_resource_group[0].name
  location            = azurerm_resource_group.machines_resource_group[0].location
  vm_size             = var.ctx_vm_size
  network_interface_ids = [
    azurerm_network_interface.windows_vda_nic[count.index].id,
  ]

  storage_os_disk {
    name              = azurerm_managed_disk.windows_vda_osdisk[count.index].name
    caching           = "ReadWrite"
    os_type           = "Windows"
    create_option     = "Attach"
    managed_disk_id   = azurerm_managed_disk.windows_vda_osdisk[count.index].id
    managed_disk_type = "Standard_LRS"
  }

  os_profile_windows_config {
    provision_vm_agent = true
  }

  depends_on = [
    azurerm_network_interface.windows_vda_nic,
    azurerm_managed_disk.windows_vda_osdisk
  ]
}

resource "azurerm_virtual_machine_extension" "rename_vda_hostname" {
  count                = var.vda_machine_count
  name                 = "rename-vda-hostname"
  virtual_machine_id   = azurerm_virtual_machine.vda[count.index].id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.9"
  # The Azure client, subscription, and tenant id can be replaced with Customer's own Azure credentcial
  protected_settings = <<PROTECTED_SETTINGS
  {
      "commandToExecute": "powershell -ExecutionPolicy Unrestricted -Command \"Rename-Computer -NewName ${azurerm_virtual_machine.vda[count.index].name} -Restart -Force\""
  }
  PROTECTED_SETTINGS

  depends_on = [
    azurerm_virtual_machine.vda
  ]
}



resource "azurerm_virtual_machine_extension" "vda_domain_join" {
  count = var.vda_machine_count

  name                       = "vda-domain-join"
  virtual_machine_id         = azurerm_virtual_machine.vda[count.index].id
  publisher                  = "Microsoft.Compute"
  type                       = "JsonADDomainExtension"
  type_handler_version       = "1.3"
  auto_upgrade_minor_version = true

  settings = <<SETTINGS
    {
      "Name": "${var.active_directory_domain_name}",
      "User": "${var.advm_admin_username}@${var.active_directory_domain_name}",
      "Restart": "true",
      "Options": "3"
    }
  SETTINGS

  protected_settings = <<SETTINGS
    {
      "Password": "${local.advm_admin_password}"
    }
  SETTINGS
  depends_on = [
    azurerm_virtual_machine_extension.advm_dsc,
    azurerm_virtual_machine_extension.rename_vda_hostname
  ]
}

resource "azurerm_virtual_machine_extension" "windows_vda_setup_extension" {
  count = var.vda_machine_count

  name                 = "configure-vda-ssl"
  virtual_machine_id   = azurerm_virtual_machine.vda[count.index].id
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"

  settings = <<SETTINGS
    {
      "configuration": {
        "function": "VdaSetup",
        "script": "New-VdaSetup.ps1",
        "url": "${azurerm_storage_blob.vda_setup_script_zip[0].url}"
      },
      "configurationArguments": {
        "ExpectedComputerName"        : "${azurerm_virtual_machine.vda[count.index].name}",
        "ADDomainFQDN"                : "${var.active_directory_domain_name}",
        "ADDomainUsername"            : "${var.advm_admin_username}",
        "DDCList"                     : "${azurerm_windows_virtual_machine.ddc.name}.${var.active_directory_domain_name}",
        "CitrixModulesPath"           : "${var.citrix_modules_path}",
        "CAServerHostName"            : "${azurerm_windows_virtual_machine.adVM.name}",
        "CACommonName"                : "${local.cert_authority_common_name}",
        "RequestCertFromCAScriptUrl"  : "${azurerm_storage_blob.request_cert_script.url}",
        "RequestCertTemplateUrl"      : "${azurerm_storage_blob.request_template.url}",
        "EnableVdaSSLScriptUrl"       : "${azurerm_storage_blob.enable_vda_ssl_script[0].url}"
      },
      "configurationData": {
        "url": "${azurerm_storage_blob.dsc_configuration_script_data.url}"
      }
    }
  SETTINGS

  protected_settings = <<PROTECTED_SETTINGS
    {
      "configurationArguments": {
        "ADDomainPassword": "${local.advm_admin_password}"
      }
    }
  PROTECTED_SETTINGS

  depends_on = [
    azurerm_virtual_machine_extension.vda_domain_join
  ]

  timeouts {
    create = "2h"
    update = "2h"
  }
}