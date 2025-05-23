// Policy is depending on the policy set
resource "citrix_policy" "html5_websocket_policy" {
    policy_set_id   = citrix_policy_set_v2.html5_websocket_policy_set.id
    name            = "HTML5 WebSocket Policy for ${citrix_delivery_group.onprem_delivery_group.name}"
    enabled         = true
}
