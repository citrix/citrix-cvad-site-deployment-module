output "resource_group_information" {
    value = {
        "cvad_components_resource_group_name": azurerm_resource_group.ctx_resource_group.name,
        "cvad_setup_storage_account_name": azurerm_storage_account.setup_storage.name,
        "cvad_vnet_name": azurerm_virtual_network.cvad_vnet.name
    }
}

output "active_directory_information" {
    value = {
        "domain_name": var.active_directory_domain_name,
        "domain_admin_username": var.advm_admin_username,
        "domain_admin_password": local.advm_admin_password,
        "domain_user_default_password": local.ad_default_user_password
    }
    sensitive = true
}

output "domain_controller_details" {
    value = {
        "vm_machine_name": azurerm_windows_virtual_machine.adVM.name,
        "public_ip": azurerm_windows_virtual_machine.adVM.public_ip_address,
        "private_ip": azurerm_windows_virtual_machine.adVM.private_ip_address
    }
}

output "ddc_details" {
    value = {
        "vm_machine_name": azurerm_windows_virtual_machine.ddc.name,
        "public_ip": azurerm_windows_virtual_machine.ddc.public_ip_address,
        "private_ip": azurerm_windows_virtual_machine.ddc.private_ip_address
    }
}

output "mssql_details" {
    value = var.setup_independent_sql_vm ? [
        for i in range(length(azurerm_windows_virtual_machine.mssql_host_vm)) :
            {
                "vm_machine_name" = azurerm_windows_virtual_machine.mssql_host_vm[i].name,
                "public_ip" = azurerm_windows_virtual_machine.mssql_host_vm[i].public_ip_address,
                "private_ip" = azurerm_windows_virtual_machine.mssql_host_vm[i].private_ip_address
            }
    ] : []
}

output "webstudio_details" {
    value = [
        for i in range(length(azurerm_windows_virtual_machine.webstudio)) :
            {
                "vm_machine_name" = azurerm_windows_virtual_machine.webstudio[i].name,
                "public_ip" = azurerm_windows_virtual_machine.webstudio[i].public_ip_address,
                "private_ip" = azurerm_windows_virtual_machine.webstudio[i].private_ip_address
            }
    ]
}

output "storefront_details" {
    value = [
        for i in range(length(azurerm_windows_virtual_machine.storefront)) :
            {
                "vm_machine_name" = azurerm_windows_virtual_machine.storefront[i].name,
                "public_ip" = azurerm_windows_virtual_machine.storefront[i].public_ip_address,
                "private_ip" = azurerm_windows_virtual_machine.storefront[i].private_ip_address
            }
    ]
}

output "license_server_details" {
    value = var.setup_independent_license_server ? [
        for i in range(length(azurerm_windows_virtual_machine.license_server)) :
            {
                "vm_machine_name" = azurerm_windows_virtual_machine.license_server[i].name,
                "public_ip" = azurerm_windows_virtual_machine.license_server[i].public_ip_address,
                "private_ip" = azurerm_windows_virtual_machine.license_server[i].private_ip_address
            }
    ] : []
}

output "director_details" {
    value = [
        for i in range(length(azurerm_windows_virtual_machine.director)) :
            {
                "vm_machine_name" = azurerm_windows_virtual_machine.director[i].name,
                "public_ip" = azurerm_windows_virtual_machine.director[i].public_ip_address,
                "private_ip" = azurerm_windows_virtual_machine.director[i].private_ip_address
            }
    ]
}

output "site_information" {
    value = {
        "default_webstudio_machine_name": "${var.webstudio_count == 0 ? azurerm_windows_virtual_machine.ddc.name : azurerm_windows_virtual_machine.webstudio[0].name}",
        "webstudio_address_2308_or_earlier": "https://${var.webstudio_count == 0 ? azurerm_windows_virtual_machine.ddc.name : azurerm_windows_virtual_machine.webstudio[0].name}.${var.active_directory_domain_name}/Citrix/WebStudio/",
        "webstudio_address_2311_or_later": "https://${var.webstudio_count == 0 ? azurerm_windows_virtual_machine.ddc.name : azurerm_windows_virtual_machine.webstudio[0].name}.${var.active_directory_domain_name}/Citrix/Studio/",
        "storefront_address": "${local.storefront_host_base_address}${var.store_virtual_path}Web/"
        "storefront_virtual_path": var.store_virtual_path
    }
    sensitive = true
}

output "local_temp_file_information" {
    value = {
        "local_temp_file_dir": var.local_temp_file_dir
    }
}
