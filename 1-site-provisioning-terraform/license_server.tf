resource "azurerm_public_ip" "license_server_public_ip" {
  count               = var.setup_independent_license_server ? 1 : 0
  name                = "${var.license_server_machine_name}-pip"
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
  location            = azurerm_resource_group.ctx_resource_group.location
  allocation_method   = "Static"
}

resource "azurerm_network_interface" "license_server_nic" {
  count               = var.setup_independent_license_server ? 1 : 0
  name                = "${var.license_server_machine_name}-nic"
  location            = azurerm_resource_group.ctx_resource_group.location
  resource_group_name = azurerm_resource_group.ctx_resource_group.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.cvad_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.license_server_public_ip[count.index].id
  }

  depends_on = [
    azurerm_network_interface.adVM_nic,
    azurerm_network_interface.webstudio_nic,
    azurerm_network_interface.ddc_nic,
    azurerm_network_interface.mssql_vm_nic,
    azurerm_network_interface.director_nic
  ]
}

resource "azurerm_network_interface_security_group_association" "license_server_nsg" {
  count                     = var.setup_independent_license_server ? 1 : 0
  network_interface_id      = azurerm_network_interface.license_server_nic[count.index].id
  network_security_group_id = azurerm_network_security_group.vnet_security_group.id
}

resource "azurerm_windows_virtual_machine" "license_server" {
  count               = var.setup_independent_license_server ? 1 : 0
  name                = var.license_server_machine_name
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
  location            = azurerm_resource_group.ctx_resource_group.location
  size                = var.ctx_vm_size
  admin_username      = var.license_server_admin_username
  admin_password      = local.license_server_admin_password
  network_interface_ids = [
    azurerm_network_interface.license_server_nic[count.index].id
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

resource "azurerm_virtual_machine_extension" "license_server_setup_extension" {
  count               = var.setup_independent_license_server ? 1 : 0
  name                 = "${azurerm_windows_virtual_machine.license_server[count.index].name}-setup"
  virtual_machine_id   = azurerm_windows_virtual_machine.license_server[count.index].id
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"

  settings = <<SETTINGS
    {
      "configuration": {
        "function": "CVADInstallation",
        "script": "Install-CVAD.ps1",
        "url": "${azurerm_storage_blob.install_cvad_script_zip.url}"
      },
      "configurationArguments": ${jsonencode({
        "ComponentList"                  = "LICENSESERVER",
        "ADDomainFQDN"                   = "${var.active_directory_domain_name}",
        "ADDomainUsername"               = "${var.advm_admin_username}",
        "AdDomainControllerPrivateIp"    = "${var.ad_private_ip_addr}",
        "CVADInstallerDownloadUrl"       = "${local.cvad_installer_iso_url}",
        "CVADInstallerMd5Hash"           = "${local.cvad_installer_iso_md5}",
        "DefaultControllerName"          = "${azurerm_windows_virtual_machine.ddc.name}",
        "CitrixModulesPath"              = "${var.citrix_modules_path}",
        "CAServerHostName"               = "${azurerm_windows_virtual_machine.adVM.name}",
        "CACommonName"                   = "${local.cert_authority_common_name}",
        "RequestCertFromCAScriptUrl"     = "${azurerm_storage_blob.request_cert_script.url}",
        "RequestCertTemplateUrl"         = "${azurerm_storage_blob.request_template.url}",
        "LicenseFileUri"                 = "${length(var.license_file_path) > 0 ? azurerm_storage_blob.cvad_license_file[0].url : ""}"
      })},
      "configurationData": {
        "url": "${azurerm_storage_blob.dsc_configuration_script_data.url}"
      }
    }
  SETTINGS

  protected_settings = <<PROTECTED_SETTINGS
    {
      "configurationArguments": {
        "LicenseCertPassword": "${random_password.license_cert_password.result}",
        "ADDomainPassword": "${local.advm_admin_password}"
      }
    }
  PROTECTED_SETTINGS

  depends_on = [
    azurerm_virtual_machine_extension.advm_dsc
  ]

  timeouts {
    create = "1h"
    update = "1h"
  }
}
