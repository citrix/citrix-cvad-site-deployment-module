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
  name                  = "setupscripts"
  storage_account_name  = azurerm_storage_account.setup_storage.name
  container_access_type = "blob"
}

resource "azurerm_storage_container" "vda_image_container" {
  count = var.vda_machine_count == 0 ? 0 : 1

  name                  = local.vda_image_container_name
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

data "archive_file" "ddc_setup" {
  type        = "zip"
  source_dir  = "${local.setup_folder_path}DSCScripts/DDCSetup/"
  output_path = "${var.local_temp_file_dir}dsc-archives/DDC-Setup.ps1.zip"
}

resource "azurerm_storage_blob" "ddc_setup_script_zip" {
  name                   = "DDC-Setup.ps1.zip"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = data.archive_file.ddc_setup.output_path
  content_md5            = data.archive_file.ddc_setup.output_md5
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

#region Multi Storefront Custom Script Extensions
data "archive_file" "sf_setup" {
  count = var.storefront_vm_count == 0 ? 0 : 1

  type        = "zip"
  source_dir  = "${local.setup_folder_path}DSCScripts/SFSetup/"
  output_path = "${var.local_temp_file_dir}dsc-archives/SF-Setup.ps1.zip"
}

resource "azurerm_storage_blob" "sf_setup_script_zip" {
  count = var.storefront_vm_count == 0 ? 0 : 1

  name                   = "SF-Setup.ps1.zip"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = data.archive_file.sf_setup[0].output_path
  content_md5            = data.archive_file.sf_setup[0].output_md5
}
#endregion

#region Director Custom Script Extensions
data "archive_file" "director_setup" {
  count = var.director_count == 0 ? 0 : 1

  type        = "zip"
  source_dir  = "${local.setup_folder_path}DSCScripts/DirectorSetup/"
  output_path = "${var.local_temp_file_dir}dsc-archives/Director-Setup.ps1.zip"
}

resource "azurerm_storage_blob" "director_setup_script_zip" {
  count = var.director_count == 0 ? 0 : 1

  name                   = "Director-Setup.ps1.zip"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = data.archive_file.director_setup[0].output_path
  content_md5            = data.archive_file.director_setup[0].output_md5
}
#endregion

#region CVAD License
resource "azurerm_storage_blob" "cvad_license_file" {
  count                  = local.license_file_provided ? 1 : 0
  name                   = basename(var.license_file_path)
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = var.license_file_path
  content_md5            = filemd5("${var.license_file_path}")
}
#endregion

#region WebStudio DSC Script Extensions
data "archive_file" "webstudio_setup" {
  count = var.webstudio_count == 0 ? 0 : 1

  type        = "zip"
  source_dir  = "${local.setup_folder_path}DSCScripts/WebStudioSetup/"
  output_path = "${var.local_temp_file_dir}dsc-archives/WebStudio-Setup.ps1.zip"
}

resource "azurerm_storage_blob" "webstudio_setup_script_zip" {
  count = var.webstudio_count == 0 ? 0 : 1

  name                   = "WebStudio-Setup.ps1.zip"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = data.archive_file.webstudio_setup[0].output_path
  content_md5            = data.archive_file.webstudio_setup[0].output_md5
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

#region VDA DSC Script Extensions
data "archive_file" "vda_setup" {
  count = var.vda_machine_count == 0 ? 0 : 1

  type        = "zip"
  source_dir  = "${local.setup_folder_path}DSCScripts/VdaSetup/"
  output_path = "${var.local_temp_file_dir}dsc-archives/New-VdaSetup.ps1.zip"
}

resource "azurerm_storage_blob" "vda_setup_script_zip" {
  count = var.vda_machine_count == 0 ? 0 : 1

  name                   = "New-VdaSetup.ps1.zip"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = data.archive_file.vda_setup[0].output_path
  content_md5            = data.archive_file.vda_setup[0].output_md5
}

resource "azurerm_storage_blob" "enable_vda_ssl_script" {
  count = var.vda_machine_count == 0 ? 0 : 1

  name                   = "Enable-VdaSSL.ps1"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = "${local.setup_folder_path}CustomScripts/Enable-VdaSSL.ps1"
  content_md5            = filemd5("${local.setup_folder_path}CustomScripts/Enable-VdaSSL.ps1")
}
#endregion

#region VHD images
resource "azurerm_storage_blob" "vda_image" {
  count = var.vda_machine_count == 0 ? 0 : 1

  name                   = local.destination_image_name
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.vda_image_container[0].name
  type                   = "Page"
  source_uri             = local.image_source_link

  timeouts {
    create = "90m"
    update = "90m"
  }
}
#endregion

#region CVAD installer ISO blob
resource "azurerm_storage_blob" "cvad_installer_iso" {
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
