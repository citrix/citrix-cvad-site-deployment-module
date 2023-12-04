resource "azurerm_virtual_machine_extension" "set_delivery_group_ssl" {
  name                 = "set-delivery-group-ssl"
  virtual_machine_id   = data.azurerm_virtual_machine.ddc.id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.9"
  protected_settings   = <<PROTECTED_SETTINGS
    {
      "commandToExecute": "powershell.exe -Command \"./Set-DeliveryGroupHdxSSL.ps1 -DeliveryGroup ${var.delivery_group_name} -DomainAdminUsername \"${var.active_directory_domain_name}\\${var.advm_admin_username}\" -DomainAdminPassword '${var.advm_admin_password}'\""
    }
  PROTECTED_SETTINGS

  settings = <<SETTINGS
    {
        "fileUris": [
            "${azurerm_storage_blob.set_delivery_group_ssl.url}"
        ]
    }
  SETTINGS

  depends_on = [ 
    citrix_daas_delivery_group.onprem_delivery_group
   ]
}
