resource "citrix_delivery_group_policy_filter" "delivery_group_filter" {
    policy_id          = citrix_policy.html5_websocket_policy.id
    enabled            = true
    allowed            = true
    delivery_group_id  = citrix_delivery_group.onprem_delivery_group.id
}