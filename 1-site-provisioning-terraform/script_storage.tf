resource "random_id" "storage" {
  byte_length = 4
}

resource "azurerm_storage_account" "setup_storage" {
  name                     = "${local.cvad_setup_storage_name}${random_id.storage.hex}"
  resource_group_name      = azurerm_resource_group.ctx_resource_group.name
  location                 = azurerm_resource_group.ctx_resource_group.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "setup_script_container" {
  name                  = var.setup_script_container_name
  storage_account_name  = azurerm_storage_account.setup_storage.name
  container_access_type = "blob"
}

#region DSC scripts
data "archive_file" "MSSQLSetup" {
  count = var.setup_independent_sql_vm ? 1 : 0

  type        = "zip"
  source_dir  = "${local.setup_folder_path}DSCScripts/MsSqlSetup/"
  output_path = "${var.local_temp_file_dir}dsc-archives/MSSQL-Setup.ps1.zip"
}

resource "azurerm_storage_blob" "mssql_setup_script_zip" {
  count = var.setup_independent_sql_vm ? 1 : 0

  name                   = "MSSQL-Setup.ps1.zip"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = data.archive_file.MSSQLSetup[0].output_path
  content_md5            = data.archive_file.MSSQLSetup[0].output_md5
}

data "archive_file" "domain_controller_setup_script" {
  type        = "zip"
  source_dir  = "${local.setup_folder_path}DSCScripts/ADDCSetup/"
  output_path = "${var.local_temp_file_dir}dsc-archives/New-ADDCSetup.ps1.zip"
}

resource "azurerm_storage_blob" "domain_controller_setup_script_zip" {
  name                   = "New-ADDCSetup.ps1.zip"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = data.archive_file.domain_controller_setup_script.output_path
  content_md5            = data.archive_file.domain_controller_setup_script.output_md5
}

data "archive_file" "install_cvad" {
  type        = "zip"
  source_dir  = "${local.setup_folder_path}DSCScripts/Install-CVAD/"
  output_path = "${var.local_temp_file_dir}dsc-archives/Install-CVAD.ps1.zip"
}

resource "azurerm_storage_blob" "install_cvad_script_zip" {
  name                   = "Install-CVAD.ps1.zip"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = data.archive_file.install_cvad.output_path
  content_md5            = data.archive_file.install_cvad.output_md5
}

resource "azurerm_storage_blob" "dsc_configuration_script_data" {
  name                   = "DSC-Configuration.psd1"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = "${local.setup_folder_path}ConfigurationData/DSC-Configuration.psd1"
  content_md5            = filemd5("${local.setup_folder_path}ConfigurationData/DSC-Configuration.psd1")
}
#endregion

#region CVAD License
resource "azurerm_storage_blob" "cvad_license_file" {
  count                  = length(var.license_file_path) > 0 ? 1 : 0
  name                   = basename(var.license_file_path)
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = var.license_file_path
  content_md5            = filemd5("${var.license_file_path}")
}
#endregion

#region AD Cert Authority Custom Script
resource "azurerm_storage_blob" "install_ad_cert_authority_script" {
  name                   = "Install-ADCertificationAuthority.ps1"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = "${local.setup_folder_path}CustomScripts/Install-ADCertificationAuthority.ps1"
  content_md5            = filemd5("${local.setup_folder_path}CustomScripts/Install-ADCertificationAuthority.ps1")
}
#endregion

#region Certification Request Custom Scripts and Data
resource "azurerm_storage_blob" "request_cert_script" {
  name                   = "Request-CertificateFromCA.ps1"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = "${local.setup_folder_path}CustomScripts/Request-CertificateFromCA.ps1"
  content_md5            = filemd5("${local.setup_folder_path}CustomScripts/Request-CertificateFromCA.ps1")
}

resource "azurerm_storage_blob" "request_template" {
  name                   = "RequestTemplate.inf"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = "${local.setup_folder_path}ConfigurationData/RequestTemplate.inf"
  content_md5            = filemd5("${local.setup_folder_path}ConfigurationData/RequestTemplate.inf")
}
#endregion

#region CVAD installer ISO blob
resource "azurerm_storage_blob" "cvad_installer_iso" {
  count                  = var.is_cvad_installer_stored_locally ? 1 : 0
  name                   = "CVAD_Installer.iso"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = var.cvad_installer_iso_file_path
  content_md5            = filemd5(var.cvad_installer_iso_file_path)

  timeouts {
    create = "90m"
    update = "90m"
  }
}
#endregion
