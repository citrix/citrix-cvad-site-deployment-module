output "machine_catalog_information" {
    value = {
        "machine_catalog_name": citrix_daas_machine_catalog.onprem_catalog.name,
        "machine_catalog_session_support": var.catalog_session_support,
        "vda_resource_group_name": var.vda_resource_group_name,
        "vda_count_in_catalog": citrix_daas_machine_catalog.onprem_catalog.provisioning_scheme.number_of_total_machines
    }
}

output "delivery_group_information" {
    value = {
        "delivery_group_name": citrix_daas_delivery_group.onprem_delivery_group.name,
        "delivery_group_users": citrix_daas_delivery_group.onprem_delivery_group.users,
        "vda_count_in_delivery_group": citrix_daas_delivery_group.onprem_delivery_group.total_machines
        "autoscale_enabled": citrix_daas_delivery_group.onprem_delivery_group.autoscale_enabled
    }
}
