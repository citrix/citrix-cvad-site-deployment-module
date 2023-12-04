resource "citrix_daas_hypervisor" "azure_hypervisor" {
    name                = var.ddc_hypervisor_connection_name
    connection_type     = "AzureRM"
    zone                = citrix_daas_zone.azure_zone.id
    application_id      = var.azure_client_id
    application_secret  = var.azure_client_secret
    subscription_id     = var.azure_subscription_id
    active_directory_id = var.azure_tenant_id
}
