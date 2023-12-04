resource "azurerm_virtual_machine_extension" "vda_ssl_configuration" {
  for_each = toset([
        for vda in data.azurerm_virtual_machine.vdas_to_enable_ssl:
            vda.id
    ])
  name                 = "configure-vda-ssl"
  virtual_machine_id   = each.value
  publisher            = "Microsoft.Powershell"
  type                 = "DSC"
  type_handler_version = "2.77"

  settings = <<SETTINGS
    {
      "configuration": {
        "function": "VdaSetup",
        "script": "Set-VdaSSL.ps1",
        "url": "${azurerm_storage_blob.vda_setup_script_zip.url}"
      },
      "configurationArguments": ${jsonencode({
        "ADDomainFQDN"                = "${var.active_directory_domain_name}",
        "ADDomainUsername"            = "${var.advm_admin_username}",
        "DDCList"                     = "${var.ddc_machine_name}.${var.active_directory_domain_name}",
        "CAServerHostName"            = "${var.advm_machine_name}",
        "CACommonName"                = "${local.cert_authority_common_name}",
        "RequestCertFromCAScriptUrl"  = "${data.azurerm_storage_blob.request_cert_script.url}",
        "RequestCertTemplateUrl"      = "${data.azurerm_storage_blob.request_template.url}",
        "EnableVdaSSLScriptUrl"       = "${azurerm_storage_blob.enable_vda_ssl_script.url}"
      })},
      "configurationData": {
        "url": "${data.azurerm_storage_blob.dsc_configuration_script_data.url}"
      }
    }
  SETTINGS

  protected_settings = <<PROTECTED_SETTINGS
    {
      "configurationArguments": {
        "ADDomainPassword": "${var.advm_admin_password}"
      }
    }
  PROTECTED_SETTINGS

  timeouts {
    create = "2h"
    update = "2h"
  }
}
