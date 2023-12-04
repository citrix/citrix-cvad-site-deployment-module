resource "local_file" "stage_marker" {
    filename = "${var.local_temp_file_dir}stage_marker.json"
    content = jsonencode({
        "provisioning" = true,
        "management" = true,
        "vda_ssl" = false
    })

    depends_on = [ 
        azurerm_virtual_machine_extension.set_delivery_group_ssl
     ]
}
