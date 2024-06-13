resource "random_password" "citrix_cloud_connector_vm_pwd" { #gitleaks:allow
  length           = 32
  special          = true
  override_special = "@#%^&*-_!+=?:;,."
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}
