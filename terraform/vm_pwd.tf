resource "random_password" "advm_admin_password" { #gitleaks:allow
  length           = 32
  special          = true
  override_special = local.vm_password_special_characters
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

resource "random_password" "ad_default_user_password" { #gitleaks:allow
  length           = 32
  special          = true
  override_special = local.vm_password_special_characters
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

resource "random_password" "ddc_admin_password" { #gitleaks:allow
  length           = 32
  special          = true
  override_special = local.vm_password_special_characters
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

resource "random_password" "mssql_admin_password" { #gitleaks:allow
  count = var.setup_independent_sql_vm ? 1 : 0

  length           = 32
  special          = true
  override_special = local.vm_password_special_characters
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

resource "random_password" "sql_connectivity_password" { #gitleaks:allow
  count = var.setup_independent_sql_vm ? 1 : 0

  length           = 32
  special          = true
  override_special = local.vm_password_special_characters
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

resource "random_password" "storefront_password" { #gitleaks:allow
  count = var.storefront_vm_count == 0 ? 0 : 1

  length           = 32
  special          = true
  override_special = local.vm_password_special_characters
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

resource "random_password" "director_password" { #gitleaks:allow
  count = var.director_count == 0 ? 0 : 1

  length           = 32
  special          = true
  override_special = local.vm_password_special_characters
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

resource "random_password" "webstudio_password" { #gitleaks:allow
  count = var.webstudio_count == 0 ? 0 : 1

  length           = 32
  special          = true
  override_special = local.vm_password_special_characters
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

resource "random_password" "vda_password" { #gitleaks:allow
  count = var.vda_machine_count == 0 ? 0 : 1

  length           = 32
  special          = true
  override_special = local.vm_password_special_characters
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  min_upper        = 1
}

