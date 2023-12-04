resource "local_file" "stage_marker" {
    filename = "${var.local_temp_file_dir}stage_marker.json"
    content = jsonencode({
        "provisioning" = true,
        "management" = false,
        "vda_ssl" = false
    })

    depends_on = [ 
        azurerm_virtual_machine_extension.webstudio_setup_extension,
        azurerm_virtual_machine_extension.storefront_setup_extension,
        azurerm_virtual_machine_extension.director_setup_extension,
        azurerm_virtual_machine_extension.ddc_setup_extension
     ]
}
