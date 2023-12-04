locals {
  setup_folder_path          = "../Setup/"
  cvad_setup_storage_name    = replace("${var.resource_prefix}storage", "-", "")
  cert_authority_common_name = replace("${var.active_directory_domain_name}-CA", ".", "-")
    
  cvad_installer_iso_url = var.is_cvad_installer_stored_locally ? azurerm_storage_blob.cvad_installer_iso[0].url : var.cvad_installer_iso_file_path
  cvad_installer_iso_md5 = var.is_cvad_installer_stored_locally ? azurerm_storage_blob.cvad_installer_iso[0].content_md5 : var.cvad_installer_iso_file_md5

  database_server_name = var.setup_independent_sql_vm ? var.mssql_machine_name : "${var.ddc_machine_name}\\SQLEXPRESS"
  ad_net_bios_name     = upper(split(".", var.active_directory_domain_name)[0])

  storefront_host_base_address = "https://${var.storefront_vm_count == 0 ? azurerm_windows_virtual_machine.ddc.name : azurerm_windows_virtual_machine.storefront[0].name}.${var.active_directory_domain_name}"

  # If user specified license server address, then they are bring in their own license server
  # Otherwise, we check if an independent license server will be setup. If so, use the address of that license server
  # If non of those scenarios apply, we are using the license server setup on DDC
  license_server_address = (length(var.license_server_address) > 0 ? 
                            var.license_server_address : 
                              var.setup_independent_license_server ?
                                "${azurerm_windows_virtual_machine.license_server[0].name}.${var.active_directory_domain_name}" :
                                "127.0.0.1")

  vm_password_special_characters = "@#%^*-_!+=?:;,."
  advm_admin_password            = length(var.advm_admin_password) == 0 ? random_password.advm_admin_password.result : var.advm_admin_password
  ad_default_user_password       = length(var.ad_default_user_password) == 0 ? random_password.ad_default_user_password.result : var.ad_default_user_password
  ddc_admin_password             = length(var.ddc_admin_password) == 0 ? random_password.ddc_admin_password.result : var.ddc_admin_password
  mssql_admin_password           = (length(var.mssql_admin_password) == 0 && var.setup_independent_sql_vm ?
                                      random_password.mssql_admin_password[0].result :
                                      var.mssql_admin_password)
  sql_connectivity_password      = (length(var.sql_connectivity_password) == 0 && var.setup_independent_sql_vm ?
                                      random_password.sql_connectivity_password[0].result :
                                      var.sql_connectivity_password)
  license_server_admin_password  = (length(var.license_server_admin_password) == 0 && var.setup_independent_license_server ?
                                      random_password.license_server_admin_password[0].result :
                                      var.license_server_admin_password)
  storefront_password            = (length(var.storefront_password) == 0 && var.storefront_vm_count > 0 ?
                                      random_password.storefront_password[0].result :
                                      var.storefront_password)
  director_password              = (length(var.director_password) == 0 && var.director_count > 0 ?
                                      random_password.director_password[0].result :
                                      var.director_password)
  webstudio_password             = (length(var.webstudio_password) == 0 && var.webstudio_count > 0 ?
                                      random_password.webstudio_password[0].result :
                                      var.webstudio_password)
}
