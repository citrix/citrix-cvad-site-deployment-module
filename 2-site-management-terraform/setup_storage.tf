#region VHD images

resource "azurerm_storage_container" "vda_image_container" {
  name                  = var.vda_image_container_name
  storage_account_name  = var.setup_storage_account_name
  container_access_type = "blob"
}

resource "azurerm_storage_blob" "vda_image" {
  name                   = var.destination_vda_image_name
  storage_account_name   = var.setup_storage_account_name
  storage_container_name = azurerm_storage_container.vda_image_container.name
  type                   = "Page"
  source_uri             = var.vda_image_source_link

  timeouts {
    create = "90m"
    update = "90m"
  }
}
#endregion

#region Enable SSL for Delivery Group script
resource "azurerm_storage_blob" "set_delivery_group_ssl" {
  name                   = "Set-DeliveryGroupHdxSSL.ps1"
  storage_account_name   = var.setup_storage_account_name
  storage_container_name = var.setup_script_container_name
  type                   = "Block"
  source                 = "${local.setup_folder_path}CustomScripts/Set-DeliveryGroupHdxSSL.ps1"
  content_md5            = filemd5("${local.setup_folder_path}CustomScripts/Set-DeliveryGroupHdxSSL.ps1")
}
#endregion

