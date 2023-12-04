resource "citrix_daas_delivery_group" "onprem_delivery_group" {
  name = var.delivery_group_name
  associated_machine_catalogs = [
    {
      machine_catalog = citrix_daas_machine_catalog.onprem_catalog.id
      machine_count   = var.vda_machine_count
    }
  ]
  users = var.desktop_user_upns
}
