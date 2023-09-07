locals {
  setup_folder_path          = "../Setup/"
  cvad_setup_storage_name    = replace("${var.resource_prefix}storage", "-", "")
  cert_authority_common_name = replace("${var.active_directory_domain_name}-CA", ".", "-")
  default_catalog_user_list  = "user0001,user0002,user0003"
  
  license_file_provided = length(var.license_file_path) > 0 && endswith(var.license_file_path, ".lic")

  database_server_name = var.setup_independent_sql_vm ? var.mssql_machine_name : "${var.ddc_machine_name}\\\\SQLEXPRESS"
  ad_net_bios_name     = upper(split(".", var.active_directory_domain_name)[0])

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
  storefront_password            = (length(var.storefront_password) == 0 && var.storefront_vm_count > 0 ?
                                      random_password.storefront_password[0].result :
                                      var.storefront_password)
  director_password              = (length(var.director_password) == 0 && var.director_count > 0 ?
                                      random_password.director_password[0].result :
                                      var.director_password)
  webstudio_password             = (length(var.webstudio_password) == 0 && var.webstudio_count > 0 ?
                                      random_password.webstudio_password[0].result :
                                      var.webstudio_password)
  vda_password                   = (length(var.vda_password) == 0 && var.vda_machine_count > 0 && local.license_file_provided ?
                                      random_password.vda_password[0].result :
                                      var.vda_password)

  # Machine Creation Settings
  vda_image_container_name = "vda-images"
  image_source_link        = (var.catalog_session_support == "MultiSession" ? 
                              "" :
                              "")
  destination_image_name   = "vda-image.vhd"
  hyper_v_generation       = "V2"

  deployment_summary_vda_resource_group_name = var.vda_machine_count == 0 ? "" : azurerm_resource_group.machines_resource_group[0].name
}
