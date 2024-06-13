locals {
      setup_folder_path          = "../Setup/"
      citrix_cloud_connector_vm_pwd = length(var.citrix_cloud_connector_vm_pwd) == 0 ? random_password.citrix_cloud_connector_vm_pwd.result : var.citrix_cloud_connector_vm_pwd
}
