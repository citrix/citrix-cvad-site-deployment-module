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

variable "hide_session_launch_password" {
  type        = bool
  description = "Indicating whether session launch password will be hidden in the powershell console after deployment"
  default     = false
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

################################################################################
#                                                                              #
#                            Azure VNet Settings                               #
#                                                                              #
################################################################################
variable "cvad_vnet_name" {
  type        = string
  description = "Name of the Virtual Network (VNet) that CVAD components will join."
  default     = "ctx-cvad-vnet"
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
#                           CVAD Zone Configurations                           #
#                                                                              #
################################################################################

variable "vda_zone_name" {
  type        = string
  description = "Name of the Zone in Site"
  default     = "Ctx-Zone"
}

variable "vda_zone_description" {
  type        = string
  description = "Description of the Zone in Site"
  default     = "Citrix Virtual Apps and Desktops Zone for VDAs"
}

################################################################################
#                                                                              #
#                       Hypervisor Connection Settings                         #
#                                                                              #
################################################################################

variable "ddc_hypervisor_connection_name" {
  type        = string
  description = "Name for Hypervisor Connection"
  default     = "CtxAzureConnection"
}

################################################################################
#                                                                              #
#                          DDC Resource Pool Settings                          #
#                                                                              #
################################################################################

variable "ddc_resource_pool_name" {
  type        = string
  description = "Name for Resource Pool on DDC."
  default     = "Citrix Resource Pool"
}

variable "ddc_resource_pool_region" {
  type = string
  description = "Region for the resource pool on DDC."
  default = "East US"
}

################################################################################
#                                                                              #
#                          Machine Creation Settings                           #
#                                                                              #
################################################################################

variable "vda_resource_group_name" {
  type        = string
  description = "Name of the resource group where Virtual Delivery Agents (VDAs) components will be created in."
  default     = "ctx-vda-resource-group"
}

variable "machine_catalog_name" {
  type        = string
  description = "Name of Machine Catalog Created for User"
  default     = "Ctx-Machine-Catalog"
}

variable "vda_machine_naming_scheme" {
  type        = string
  description = "Machine Naming Scheme for VDA VMs"
  default     = "ctx-vda###"
  validation {
    condition     = length(var.vda_machine_naming_scheme) <= 15
    error_message = "Naming Scheme of the VDA VM(s) can be at most 15 characters long."
  }
}

variable "vda_machine_naming_scheme_type" {
  type        = string
  description = "Machine Naming Scheme Type for VDA VMs"
  default     = "Numeric"
  validation {
    condition     = contains(["Numeric", "Alphabetic"], var.vda_machine_naming_scheme_type)
    error_message = "Naming Scheme Type of the VDA VM(s) can only be Numeric or Alphabetic."
  }
}

variable "vda_vm_size" {
  type        = string
  description = "Azure VM resource size to be used for VDAs."
  default     = "Standard_D2as_v5"
}

variable "catalog_session_support" {
  type        = string
  description = "Session support type of the Machine Catalog created for the user"
  # If license file is not provided, only single session catalog is supported
  default = "MultiSession"

  validation {
    condition     = contains(["MultiSession", "SingleSession"], var.catalog_session_support)
    error_message = "The machine catalog session support can only be MultiSession or SingleSession."
  }
}

variable "vda_osdisk_storage_type" {
  type        = string
  description = "OS Disk Storage Type for VDA Machines."
  default     = "Standard_LRS"

  validation {
    condition     = contains(["Standard_LRS", "StandardSSD_LRS", "Premium_LRS"], var.vda_osdisk_storage_type)
    error_message = "The OS Disk storage type of VDAs can only be one of Standard_LRS, StandardSSD_LRS, and Premium_LRS."
  }
}

variable "machine_allocation_type" {
  type        = string
  description = "Machine Allocation Type for Machine Catalog"
  default     = "Random"

  validation {
    condition     = contains(["Random", "Static"], var.machine_allocation_type)
    error_message = "The machine catalog allocation type can only be Random or Static."
  }
}

variable "vda_machine_count" {
  type        = number
  description = "Number of Machine Created"
  default     = 2

  validation {
    condition     = floor(var.vda_machine_count) == var.vda_machine_count && var.vda_machine_count >= 0
    error_message = "The number of VDAs could only be an integer with value greater or equals to 0."
  }
}

variable "delivery_group_name" {
  type        = string
  description = "Name of the delivery group where Virtual Delivery Agents (VDAs) will be added to."
}

################################################################################
#                                                                              #  
#                    Virtual Delivery Agent Image Settings                     #
#                                                                              #
################################################################################

variable "setup_storage_account_name" {
  type = string
  description = "Name for the storage account for delivery group setups."
}

variable "vda_image_container_name" {
  type = string
  description = "Name of the container in the temporary storage account to copy VDA image to."
  default = "vda-images"
}

variable "destination_vda_image_name" {
  type = string
  description = "Name for the VDA image in storage account."
  default = "vda-image.vhd"
}

variable "vda_image_source_link" {
  type = string
  description = "Source link url of the VDA image."
}

variable "vda_hyper_v_generation" {
  type        = string
  description = "Specifies the generation of the VDA image."
  validation {
    condition     = contains(["V1", "V2"], var.vda_hyper_v_generation)
    error_message = "The vda_hyper_v_generation variable value can only be V1 or V2"
  }
}


variable "setup_script_container_name" {
  type        = string
  description = "Name of the script container name"
}
