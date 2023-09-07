resource "azurerm_network_interface" "mssql_vm_nic" {
  count               = var.setup_independent_sql_vm ? 1 : 0
  name                = "${var.mssql_machine_name}-nic"
  location            = azurerm_resource_group.ctx_resource_group.location
  resource_group_name = azurerm_resource_group.ctx_resource_group.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.adVM_subnet.id
    private_ip_address_allocation = "Static" # Using static as mssql server is installed on this DDC
    private_ip_address            = var.mssql_private_ip_addr
  }
}

resource "azurerm_network_interface_security_group_association" "mssql_nsg" {
  count                     = var.setup_independent_sql_vm ? 1 : 0
  network_interface_id      = azurerm_network_interface.mssql_vm_nic[count.index].id
  network_security_group_id = azurerm_network_security_group.vnet_security_group.id
}

resource "azurerm_windows_virtual_machine" "mssql_host_vm" {
  count               = var.setup_independent_sql_vm ? 1 : 0
  name                = var.mssql_machine_name
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
  location            = azurerm_resource_group.ctx_resource_group.location
  size                = var.ctx_vm_size
  admin_username      = var.mssql_admin_username
  admin_password      = local.mssql_admin_password
  network_interface_ids = [
    azurerm_network_interface.mssql_vm_nic[count.index].id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "microsoftsqlserver"
    offer     = "sql2019-ws2019" # DB Version Requirements: https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/system-requirements.html#databases
    sku       = var.mssql_vm_sku
    version   = "latest"
  }

  allow_extension_operations = true
  extensions_time_budget     = "PT2H"
}

resource "azurerm_mssql_virtual_machine" "mssql" {
  count                            = var.setup_independent_sql_vm ? 1 : 0
  virtual_machine_id               = azurerm_windows_virtual_machine.mssql_host_vm[count.index].id
  sql_license_type                 = "PAYG"
  sql_connectivity_port            = 1433
  sql_connectivity_type            = "PRIVATE"
  sql_connectivity_update_password = local.sql_connectivity_password
  sql_connectivity_update_username = var.sql_connectivity_username
}

resource "azurerm_virtual_machine_extension" "mssql_setup_extention" {
  count                = var.setup_independent_sql_vm ? 1 : 0
  name                 = "${azurerm_windows_virtual_machine.mssql_host_vm[count.index].name}-setup"
  virtual_machine_id   = azurerm_windows_virtual_machine.mssql_host_vm[count.index].id
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"

  settings = <<SETTINGS
    {
      "configuration": {
        "function": "MSSQL-Setup",
        "script": "MSSQL-Setup.ps1",
        "url": "${azurerm_storage_blob.mssql_setup_script_zip[0].url}"
      },
      "configurationArguments": {
        "tempDir"                     : "C:\\CitrixTemp",
        "logFile"                     : "C:\\CitrixTemp\\MSSQL-Setup.log",
        "DbServerInstanceName"        : "${azurerm_windows_virtual_machine.mssql_host_vm[count.index].name}",
        "AdNetBIOSName"               : "${local.ad_net_bios_name}",
        "AdDomainControllerPrivateIp" : "${var.ad_private_ip_addr}",
        "AdDomainFQDN"                : "${var.active_directory_domain_name}",
        "AdDomainAdminName"           : "${var.advm_admin_username}",
        "SqlAdminUsername"            : "${var.sql_connectivity_username}"
      }
    }
  SETTINGS

  protected_settings = <<PROTECTED_SETTINGS
    {
      "configurationArguments": {
        "AdDomainAdminPassword" : "${local.advm_admin_password}",
        "SqlAdminPassword"      : "${local.sql_connectivity_password}"
      }
    }
  PROTECTED_SETTINGS

  depends_on = [
    azurerm_virtual_machine_extension.advm_dsc,
    azurerm_windows_virtual_machine.mssql_host_vm,
    azurerm_mssql_virtual_machine.mssql
  ]
}
