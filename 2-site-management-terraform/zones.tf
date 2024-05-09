resource "citrix_zone" "azure_zone" {
    name        = var.vda_zone_name
    description = var.vda_zone_description
}
