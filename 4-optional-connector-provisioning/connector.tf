# Primary Connector
resource "azurerm_network_interface" "citrix_cloud_connector_nic" {
  count               = var.citrix_cloud_connector_count
  name                = "${var.connector_vm_name}${count.index + 1}-nic"
  location            = azurerm_resource_group.ctx_connector_resource_group.location
  resource_group_name = azurerm_resource_group.ctx_connector_resource_group.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = data.azurerm_subnet.active_directory_subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface_security_group_association" "connector_nsg" {
  count                      = var.citrix_cloud_connector_count
  network_interface_id       = azurerm_network_interface.citrix_cloud_connector_nic[count.index].id
  network_security_group_id  = data.azurerm_network_security_group.active_directory_nsg.id
}

resource "azurerm_windows_virtual_machine" "citrix_cloud_connector_vm" {
  count               = var.citrix_cloud_connector_count
  name                = "${var.connector_vm_name}${count.index + 1}"
  resource_group_name = azurerm_resource_group.ctx_connector_resource_group.name
  location            = azurerm_resource_group.ctx_connector_resource_group.location
  size                = var.citrix_cloud_connector_vm_size
  admin_username      = var.connector_vm_username
  admin_password      = local.citrix_cloud_connector_vm_pwd
  network_interface_ids = [
    azurerm_network_interface.citrix_cloud_connector_nic[count.index].id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2019-Datacenter"
    version   = "latest"
  }

  allow_extension_operations = true
  extensions_time_budget     = "PT2H"
}

resource "azurerm_virtual_machine_extension" "citrix_cloud_connector_dsc" {
  count                 = var.citrix_cloud_connector_count
  name                  = "${azurerm_windows_virtual_machine.citrix_cloud_connector_vm[count.index].name}-setup"
  virtual_machine_id    = azurerm_windows_virtual_machine.citrix_cloud_connector_vm[count.index].id
  publisher             = "Microsoft.Powershell"
  type                  = "DSC"
  type_handler_version  = "2.77"

  settings = <<SETTINGS
    {
      "configuration": {
        "function": "New-ConnectorInstall",
        "script": "New-ConnectorInstall.ps1",
        "url": "${azurerm_storage_blob.connector_install_script_zip.url}"
      },
      "configurationArguments": {
        "tempDir": "C:\\CitrixTemp",
        "AdDomainControllerPrivateIp": "${var.active_directory_controller_private_ip_address}",
        "AdDomainFQDN": "${var.active_directory_domain_name}",
        "AdDomainAdminName": "${var.active_directory_admin_username}",
        "CustomerId": "${var.citrix_cloud_customer_id}",
        "ClientId": "${var.citrix_cloud_client_id}",
        "ResourceLocationId": "${citrix_cloud_resource_location.cloud_connector_resource_location.id}",
        "IsJpCustomer": ${var.citrix_cloud_jp_customer_flag}
      }
    }
  SETTINGS

  protected_settings = <<PROTECTED_SETTINGS
    {
      "configurationArguments": {
        "AdDomainAdminPassword": "${var.active_directory_admin_password}",
        "ClientSecret": "${var.citrix_cloud_client_secret}"
      }
    }
  PROTECTED_SETTINGS
}
