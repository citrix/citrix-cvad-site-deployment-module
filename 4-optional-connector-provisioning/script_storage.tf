resource "random_id" "storage" {
  byte_length = 4
}

resource "azurerm_storage_account" "setup_storage" {
  name                     = "connsetup${random_id.storage.hex}"
  resource_group_name      = azurerm_resource_group.ctx_connector_resource_group.name
  location                 = azurerm_resource_group.ctx_connector_resource_group.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "setup_script_container" {
  name                  = "connsetupscripts"
  storage_account_name  = azurerm_storage_account.setup_storage.name
  container_access_type = "blob"
}

data "archive_file" "ConnectorInstall" {
  type        = "zip"
  source_dir  = "${local.setup_folder_path}DSCScripts/ConnectorSetup/"
  output_path = "${var.local_temp_file_dir}dsc-archives/New-ConnectorInstall.ps1.zip"
}

resource "azurerm_storage_blob" "connector_install_script_zip" {
  name                   = "New-ConnectorInstall.ps1.zip"
  storage_account_name   = azurerm_storage_account.setup_storage.name
  storage_container_name = azurerm_storage_container.setup_script_container.name
  type                   = "Block"
  source                 = data.archive_file.ConnectorInstall.output_path
  content_md5            = data.archive_file.ConnectorInstall.output_md5
}
