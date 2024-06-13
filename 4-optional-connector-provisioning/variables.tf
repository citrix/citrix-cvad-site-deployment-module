################################################################################
#                                                                              #
#                           Local Temporary Settings                           #
#                                                                              #
################################################################################

variable "local_temp_file_dir" {
  type        = string
  description = "Directory to place the resources in."
  default     = "../tmp/"
}

################################################################################
#                                                                              #
#                          AzureRM Provider Settings                           #
#                                                                              #
################################################################################
variable "azure_subscription_id" {
  type        = string
  description = "Subscription to place the resources in."
}

variable "azure_client_id" {
  type        = string
  description = "SPN Client ID."
}

variable "azure_client_secret" {
  type        = string
  description = "SPN Client Secret."
  sensitive   = true
}

variable "azure_tenant_id" {
  type        = string
  description = "SPN Tenant ID."
}

variable "azure_location" {
  type        = string
  description = "Region to place the resources in."
  default     = "East US"
}

variable "azure_environment" {
  type        = string
  description = "Azure Subscription Environment (public / gov / germany)."
  default     = "public"

  validation {
    condition     = contains(["public", "gov", "germany"], var.azure_environment)
    error_message = "The azure_environment variable value can only be public, gov, or germany."
  }
}

################################################################################
#                                                                              #
#                           Active Directory Settings                          #
#                                                                              #
################################################################################

variable "active_directory_resource_group_name" {
  type        = string
  description = "Name of the resource group containing Active Directory resources."
}

variable "active_directory_subnet_name" {
  type        = string
  description = "Name of the subnet containing the Active Directory controller."
}

variable "active_directory_vnet_name" {
  type        = string
  description = "Name of the vnet containing the Active Directory controller."
}

variable "active_directory_security_group_name" {
  type        = string
  description = "Name of the security group containing the Active Directory controller."
}

variable "active_directory_controller_private_ip_address" {
  type        = string
  description = "Private IP address of the Active Directory controller."
}

variable "active_directory_domain_name" {
  type        = string
  description = "Domain name of the Active Directory."
}

variable "active_directory_admin_username" {
  type        = string
  description = "Administrator username for the Active Directory."
}

variable "active_directory_admin_password" {
  type        = string
  description = "Admin password of the Active Directory"
  sensitive   = true
}

################################################################################
#                                                                              #
#                          Citrix Connectors Settings                          #
#                                                                              #
################################################################################
variable "citrix_cloud_connector_resource_group_name" {
  type        = string
  description = "Name of the resource group to host the Citrix Cloud Connector VMs"
}

variable "connector_vm_name" {
  type        = string
  description = "Name of the connector virtual machine"
  default = "Ctx-Edge"
}

variable "connector_vm_username" {
  type        = string
  description = "Username for the connector"
}

variable "citrix_cloud_connector_vm_pwd" {
  type        = string
  description = "Password for the connector"
  sensitive   = true

  default = ""
}

variable "citrix_cloud_customer_id" {
  type        = string
  description = "Citrix cloud customer id"
}

variable "citrix_cloud_client_id" {
  type        = string
  description = "Citrix cloud client id"
}

variable "citrix_cloud_resource_location_name" {
  type        = string
  description = "Resource location name on Citrix Cloud for connector installation"
}

variable "citrix_cloud_jp_customer_flag" {
  type        = number
  description = "Define if the customer is a Japan customer"
  default     = 0
  validation {
    condition     = contains([0, 1], var.citrix_cloud_jp_customer_flag)
    error_message = "The citrix_cloud_jp_customer_flag can only be 0 or 1. 0 for False and 1 for True."
  }
}

variable "citrix_cloud_client_secret" {
  type        = string
  description = "Citrix Cloud client secret"
  sensitive   = true
}

variable "citrix_cloud_connector_count" {
  type        = number
  description = "Number of Citrix Cloud connectors to provision"
  default     = 2
}

variable "citrix_cloud_connector_vm_size" {
  type        = string
  description = "VM Size of the Citrix Cloud Connectors"
  default     = "Standard_D2as_v5"
}
