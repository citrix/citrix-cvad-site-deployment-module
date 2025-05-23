resource "citrix_delivery_group" "onprem_delivery_group" {
  name = var.delivery_group_name
  associated_machine_catalogs = [
    {
      machine_catalog = citrix_machine_catalog.onprem_catalog.id
      machine_count   = var.vda_machine_count
    }
  ]
  desktops = [
        {
            published_name = var.delivery_group_name
            restricted_access_users = {
                allow_list = [ "CTX-AD\\user0001", "CTX-AD\\advmadmin" ]
            }
            enabled = true
            enable_session_roaming = false
        }
    ] 
}
