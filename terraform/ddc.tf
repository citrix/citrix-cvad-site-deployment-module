resource "azurerm_public_ip" "ddc_public_ip" {
  name                = "${var.ddc_machine_name}-pip"
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
  location            = azurerm_resource_group.ctx_resource_group.location
  allocation_method   = "Static"
  domain_name_label   = var.ddc_dns_prefix
}

resource "azurerm_network_interface" "ddc_nic" {
  name                = "${var.ddc_machine_name}-nic"
  location            = azurerm_resource_group.ctx_resource_group.location
  resource_group_name = azurerm_resource_group.ctx_resource_group.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.adVM_subnet.id
    private_ip_address_allocation = "Static" # Using static as license server is installed on this DDC
    private_ip_address            = var.ddc_private_ip_addr
    public_ip_address_id          = azurerm_public_ip.ddc_public_ip.id
  }
}

resource "azurerm_network_interface_security_group_association" "ddc_nsg" {
  network_interface_id      = azurerm_network_interface.ddc_nic.id
  network_security_group_id = azurerm_network_security_group.vnet_security_group.id
}

resource "azurerm_windows_virtual_machine" "ddc" {
  name                = var.ddc_machine_name
  resource_group_name = azurerm_resource_group.ctx_resource_group.name
  location            = azurerm_resource_group.ctx_resource_group.location
  size                = var.ddc_vm_size_sku
  admin_username      = var.ddc_admin_username
  admin_password      = local.ddc_admin_password
  network_interface_ids = [
    azurerm_network_interface.ddc_nic.id,
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

resource "azurerm_virtual_machine_extension" "ddc_setup_extension" {
  name                 = "${azurerm_windows_virtual_machine.ddc.name}-setup"
  virtual_machine_id   = azurerm_windows_virtual_machine.ddc.id
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"

  settings = <<SETTINGS
    {
      "configuration": {
        "function": "CVADComponentAndSiteSetup",
        "script": "DDC-Setup.ps1",
        "url": "${azurerm_storage_blob.ddc_setup_script_zip.url}"
      },
      "configurationArguments": {
        "AdDomainControllerPrivateIp"    : "${var.ad_private_ip_addr}",
        "CAServerHostName"               : "${azurerm_windows_virtual_machine.adVM.name}",
        "ADDomainFQDN"                   : "${var.active_directory_domain_name}",
        "ADDomainUsername"               : "${var.advm_admin_username}",
        "SiteName"                       : "${var.ddc_site_name}",
        "SetupIndependentSqlVM"          : "${var.setup_independent_sql_vm}",
        "DatabaseServerName"             : "${local.database_server_name}",
        "CVADInstallerDownloadUrl"       : "${azurerm_storage_blob.cvad_installer_iso.url}",
        "CVADInstallerMd5Hash"           : "${azurerm_storage_blob.cvad_installer_iso.content_md5}",
        "CitrixModulesPath"              : "${var.citrix_modules_path}",
        "LicenseServerAddress"           : "${var.license_server_address}",
        "LicenseServerPort"              : "${var.license_server_port}",
        "StoreFrontAddress"              : "https://${var.storefront_vm_count == 0 ? azurerm_windows_virtual_machine.ddc.name : azurerm_windows_virtual_machine.storefront[0].name}.${var.active_directory_domain_name}",
        "ProductCode"                    : "${var.product_code}",
        "ProductEdition"                 : "${var.product_edition}",
        "LicenseFileUri"                 : "${local.license_file_provided ? azurerm_storage_blob.cvad_license_file[0].url : ""}",
        "StoreVirtualPath"               : "${var.store_virtual_path}",
        "SFDeliveryControllerPort"       : "${var.storefront_delivery_controller_port}",
        "FarmType"                       : "${var.farmType}",
        "FarmName"                       : "${var.farmName}",
        "FarmServers"                    : "${azurerm_windows_virtual_machine.ddc.name}.${var.active_directory_domain_name}",
        "AreDDCServersLoadBalanced"      : "${var.are_ddc_servers_load_balanced}",
        "SFStoreFriendlyName"            : "${var.storefront_store_friendly_name}",
        "ComponentList"                  : "${var.ddc_cvad_components}",
        "CACommonName"                   : "${local.cert_authority_common_name}",
        "RequestCertFromCAScriptUrl"     : "${azurerm_storage_blob.request_cert_script.url}",
        "RequestCertTemplateUrl"         : "${azurerm_storage_blob.request_template.url}",
        "AzureClientID"                  : "${var.azure_client_id}",
        "AzureClientSecret"              : "${var.azure_client_secret}",
        "AzureSubscriptionId"            : "${var.azure_subscription_id}",
        "AzureTenantId"                  : "${var.azure_tenant_id}",
        "AzureRegion"                    : "${var.azure_location}",
        "ListOfVDAs"                     : "${var.vda_machine_count == 0 ? "" : join(",", azurerm_virtual_machine.vda[*].name)}",
        "AzureVNet"                      : "${azurerm_virtual_network.vnet.name}",
        "AzureSubnet"                    : "${azurerm_subnet.adVM_subnet.name}",
        "AzureVNetResourceGroup"         : "${azurerm_resource_group.ctx_resource_group.name}",
        "VDAResourceGroup"               : "${var.vda_machine_count == 0 ? "" : azurerm_resource_group.machines_resource_group[0].name}",
        "AdNetBIOSName"                  : "${local.ad_net_bios_name}",
        "CatalogName"                    : "${var.machine_catalog_name}",
        "SessionSupport"                 : "${var.catalog_session_support}",
        "AllocationType"                 : "${var.machine_allocation_type}",
        "PersistUserChanges"             : "${var.persist_user_changes}",
        "DeliveryGroupName"              : "${var.delivery_group_name}",
        "UserGroupName"                  : "${var.ad_usergroup_name}",
        "ConnectionName"                 : "${var.ddc_connection_name}",
        "DeliveryGroupAccessPolicyName"  : "${var.access_policy_user}",
        "DesktopRuleName"                : "${var.desktop_entitle_rule}",
        "HostingName"                    : "${var.ddc_hosting_unit_name}",
        "DesktopName"                    : "${var.desktop_name}",
        "DefaultUsersInput"              : "${local.default_catalog_user_list}"
      },
      "configurationData": {
        "url": "${azurerm_storage_blob.dsc_configuration_script_data.url}"
      }
    }
  SETTINGS

  protected_settings = <<PROTECTED_SETTINGS
    {
      "configurationArguments": {
        "ADDomainPassword" : "${local.advm_admin_password}"
      }
    }
  PROTECTED_SETTINGS

  depends_on = [
    azurerm_virtual_machine_extension.advm_dsc, # This is required incase mssql is being setup in the same machine as the DDC. At that time, the mssql dsc is not executed
    azurerm_virtual_machine_extension.mssql_setup_extention,
    azurerm_virtual_machine_extension.windows_vda_setup_extension
  ]

  timeouts {
    create = "2h"
    update = "2h"
  }
}
