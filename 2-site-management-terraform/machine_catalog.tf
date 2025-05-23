resource "citrix_machine_catalog" "onprem_catalog" {
    name                        = var.machine_catalog_name
    description                 = "Description for catalog"
    zone                        = citrix_zone.azure_zone.id
    allocation_type             = var.machine_allocation_type
    session_support             = var.catalog_session_support
    provisioning_type           = "MCS"
    minimum_functional_level    = "L7_20"
    provisioning_scheme         =   {
        hypervisor = citrix_azure_hypervisor.azure_hypervisor.id
        hypervisor_resource_pool = citrix_azure_hypervisor_resource_pool.azure_resource_pool.id
        identity_type      = "ActiveDirectory"
        machine_domain_identity = {
            domain                   = var.active_directory_domain_name
            service_account          = var.advm_admin_username
            service_account_password = var.advm_admin_password
        }
        azure_machine_config = {
            storage_type = var.vda_osdisk_storage_type
            use_managed_disks = true
            service_offering = var.vda_vm_size
            azure_master_image = {
                resource_group = data.azurerm_virtual_network.cvad_component_vnet.resource_group_name
                storage_account = azurerm_storage_blob.vda_image.storage_account_name
                container = azurerm_storage_blob.vda_image.storage_container_name
                master_image = azurerm_storage_blob.vda_image.name
            }
            vda_resource_group = azurerm_resource_group.machines_resource_group.name
        }
        number_of_total_machines =  var.vda_machine_count
        machine_account_creation_rules = {
            naming_scheme      = var.vda_machine_naming_scheme
            naming_scheme_type = var.vda_machine_naming_scheme_type
        }
    }
}