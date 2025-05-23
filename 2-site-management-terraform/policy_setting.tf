// Policy Settings are depending on the `citrix_policy` resource.
// Since the `citrix_policy` resource depends on `citrix_policy_set_v2` resource, the `citrix_policy_setting` resource has an implicit dependency on the `citrix_policy_set_v2` resource.
resource "citrix_policy_setting" "accept_web_sockets_connection" {
    policy_id   = citrix_policy.html5_websocket_policy.id
    name        = "AcceptWebSocketsConnections"
    use_default = false
    enabled = true
}
