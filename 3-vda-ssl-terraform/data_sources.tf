data "azurerm_virtual_machine" "ddc" {
  name                = var.ddc_machine_name
  resource_group_name = var.cvad_component_resource_group_name
}

data "azurerm_storage_blob" "request_template" {
  name                   = "RequestTemplate.inf"
  storage_account_name   = var.setup_storage_account_name
  storage_container_name = var.setup_script_container_name
}

data "azurerm_storage_blob" "request_cert_script" {
  name                   = "Request-CertificateFromCA.ps1"
  storage_account_name   = var.setup_storage_account_name
  storage_container_name = var.setup_script_container_name
}

data "archive_file" "vda_setup" {
  type        = "zip"
  source_dir  = "${local.setup_folder_path}DSCScripts/VdaSetup/"
  output_path = "${var.local_temp_file_dir}dsc-archives/Set-VdaSSL.ps1.zip"
}

data "azurerm_storage_blob" "dsc_configuration_script_data" {
  name                   = "DSC-Configuration.psd1"
  storage_account_name   = var.setup_storage_account_name
  storage_container_name = var.setup_script_container_name
}

data "citrix_daas_vda" "vdas_in_delivery_group" {
  delivery_group = var.delivery_group_name
}

data "azurerm_virtual_machine" "vdas_to_enable_ssl" {
    for_each = toset([
        for vda in data.citrix_daas_vda.vdas_in_delivery_group.vdas:
            vda.hosted_machine_id
    ])
    name                = split("/", each.value)[1]
    resource_group_name = split("/", each.value)[0]
}
