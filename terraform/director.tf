resource "azurerm_public_ip" "director_public_ip" {
  count               = var.director_count
  name                = var.director_count > 1 ? "${var.director_machine_name}-${count.index + 1}-pip" : "${var.director_machine_name}-pip"
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
  location            = azurerm_resource_group.ctx_resource_group.location
  allocation_method   = "Static"
}

resource "azurerm_network_interface" "director_nic" {
  count               = var.director_count
  name                = var.director_count > 1 ? "${var.director_machine_name}-${count.index + 1}-nic" : "${var.director_machine_name}-nic"
  location            = azurerm_resource_group.ctx_resource_group.location
  resource_group_name = azurerm_resource_group.ctx_resource_group.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.adVM_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.director_public_ip[count.index].id
  }

  depends_on = [
    azurerm_network_interface.adVM_nic,
    azurerm_network_interface.webstudio_nic,
    azurerm_network_interface.ddc_nic,
    azurerm_network_interface.mssql_vm_nic
  ]
}


resource "azurerm_windows_virtual_machine" "director" {
  count               = var.director_count
  name                = var.director_count > 1 ? "${var.director_machine_name}-${count.index + 1}" : var.director_machine_name
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
  location            = azurerm_resource_group.ctx_resource_group.location
  size                = var.ctx_vm_size
  admin_username      = var.director_username
  admin_password      = local.director_password
  network_interface_ids = [
    azurerm_network_interface.director_nic[count.index].id,
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

resource "azurerm_virtual_machine_extension" "director_setup_extension" {
  count                = var.director_count
  name                 = "${azurerm_windows_virtual_machine.director[count.index].name}-setup"
  virtual_machine_id   = azurerm_windows_virtual_machine.director[count.index].id
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"

  settings = <<SETTINGS
    {
      "configuration": {
        "function": "DirectorSetup",
        "script": "Director-Setup.ps1",
        "url": "${azurerm_storage_blob.director_setup_script_zip[0].url}"
      },
      "configurationArguments": {
        "ADDomainFQDN"                   : "${var.active_directory_domain_name}",
        "ADDomainUsername"               : "${var.advm_admin_username}",
        "CVADInstallerDownloadUrl"       : "${azurerm_storage_blob.cvad_installer_iso.url}",
        "CVADInstallerMd5Hash"           : "${azurerm_storage_blob.cvad_installer_iso.content_md5}",
        "SiteName"                       : "${var.ddc_site_name}",
        "DDCDNSName"                     : "${azurerm_windows_virtual_machine.ddc.name}.${var.active_directory_domain_name}",
        "CitrixModulesPath"              : "${var.citrix_modules_path}",
        "CAServerHostName"               : "${azurerm_windows_virtual_machine.adVM.name}",
        "CACommonName"                   : "${local.cert_authority_common_name}",
        "RequestCertFromCAScriptUrl"     : "${azurerm_storage_blob.request_cert_script.url}",
        "RequestCertTemplateUrl"         : "${azurerm_storage_blob.request_template.url}"
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
    azurerm_virtual_machine_extension.advm_dsc,
    azurerm_network_interface_security_group_association.sfvm_nsg
  ]

  timeouts {
    create = "1h"
    update = "1h"
  }
}
