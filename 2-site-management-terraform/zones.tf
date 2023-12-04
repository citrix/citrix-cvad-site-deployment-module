resource "citrix_daas_zone" "azure_zone" {
    name        = var.vda_zone_name
    description = var.vda_zone_description
}
