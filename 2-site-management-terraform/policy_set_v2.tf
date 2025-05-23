resource "citrix_policy_set_v2" "html5_websocket_policy_set" {
    name = "HTML5 WebSocket Policy Set"
    description = "Enable WebSocket for HTML5 connections"
    scopes = []
    delivery_groups = [citrix_delivery_group.onprem_delivery_group.id]
}

resource "citrix_site_settings" "enable_policy_set_in_ui" {
    web_ui_policy_set_enabled = true
}