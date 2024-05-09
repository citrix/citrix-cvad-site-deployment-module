resource "citrix_policy_set" "html5_websocket_policy" {
    name = "HTML5 WebSocket Policy Set"
    description = "Enable WebSocket for HTML5 connections"
    type = "DeliveryGroupPolicies"
    scopes = [ "All" ]
    policies = [
        {
            name = "HTML5 WebSocket Policy for ${citrix_delivery_group.onprem_delivery_group.name}"
            enabled = true
            policy_settings = [
                {
                    name = "AcceptWebSocketsConnections"
                    enabled = true
                    use_default = false
                },
            ]
            policy_filters = [
                {
                    type = "DesktopGroup"
                    data = {
                        server = data.azurerm_virtual_machine.ddc.public_ip_address
                        uuid = citrix_delivery_group.onprem_delivery_group.id
                    }
                    enabled = true
                    allowed = true
                },
            ]
        }
    ]
}