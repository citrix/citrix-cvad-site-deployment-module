#region VDA DSC Script Extensions
resource "azurerm_storage_blob" "vda_setup_script_zip" {
  name                   = "Set-VdaSSL.ps1.zip"
  storage_account_name   = var.setup_storage_account_name
  storage_container_name = var.setup_script_container_name
  type                   = "Block"
  source                 = data.archive_file.vda_setup.output_path
  content_md5            = data.archive_file.vda_setup.output_md5
}

resource "azurerm_storage_blob" "enable_vda_ssl_script" {
  name                   = "Enable-VdaSSL.ps1"
  storage_account_name   = var.setup_storage_account_name
  storage_container_name = var.setup_script_container_name
  type                   = "Block"
  source                 = "${local.setup_folder_path}CustomScripts/Enable-VdaSSL.ps1"
  content_md5            = filemd5("${local.setup_folder_path}CustomScripts/Enable-VdaSSL.ps1")
}
#endregion
