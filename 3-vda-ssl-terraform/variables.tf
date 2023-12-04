################################################################################
#                                                                              #
#                           Local Temporary Settings                           #
#                                                                              #
################################################################################

variable "local_temp_file_dir" {
  type        = string
  description = "Subscription to place the resources in."
  default     = "../tmp/"
}

################################################################################
#                                                                              #
#              AzureRM Provider and Hypervisor Connection Settings             #
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
#                       CVAD Component Resource Settings                       #
#                                                                              #
################################################################################

variable "cvad_component_resource_group_name" {
  type        = string
  description = "Name of the resource group where the Citrix Virtual Apps and Desktops (CVAD) components will be created in."
}

variable "ddc_machine_name" {
  type        = string
  description = "Machine Name for DDC VM"
}

variable "delivery_group_name" {
  type        = string
  description = "Name of the delivery group where Virtual Delivery Agents (VDAs) will be added to."
}

################################################################################
#                                                                              #
#                             Azure AD VM Settings                             #
#                                                                              #
################################################################################
variable "advm_machine_name" {
  type        = string
  description = "Hostname for the AD VM"
}

variable "advm_admin_username" {
  type        = string
  description = "Administrator username for the AD VM"
}

variable "advm_admin_password" {
  type        = string
  description = "Admin password of the AD VM"
  sensitive   = true

  validation {
    condition = alltrue([can(regex("[0-9]+", var.advm_admin_password)), 
                         can(regex("[A-Z]+", var.advm_admin_password)), 
                         can(regex("[a-z]+", var.advm_admin_password)), 
                         can(regex("[^0-9A-Za-z]+", var.advm_admin_password)),
                         length(var.advm_admin_password) >= 8])
    error_message = "Variable advm_admin_password must satisfy the following conditions: 1. At least 8 characters; 2. At least 1 upper case letter; 3. At least 1 lower case letter; 4. At least 1 special character; 5. At least 1 numerical character."
  }
}

variable "active_directory_domain_name" {
  type        = string
  description = "Active Directory domain name"
}

################################################################################
#                                                                              #  
#                           Storage Account Settings                           #
#                                                                              #
################################################################################

variable "setup_storage_account_name" {
  type = string
  description = "Name for the storage account for delivery group setups."
  default = "vda-images"
}

variable "setup_script_container_name" {
  type        = string
  description = "Name of the script container name"
}