################################################################################
#                                                                              #
#                          AzureRM Provider Settings                           #
#                                                                              #
################################################################################

variable "local_temp_file_dir" {
  type        = string
  description = "Subscription to place the resources in."
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
#                       Azure Resource General Settings                        #
#                                                                              #
################################################################################
variable "resource_prefix" {
  type        = string
  description = "Azure resource prefix"
  default     = "ctx"
}

variable "ctx_vm_size" {
  type        = string
  description = "Azure VM resource size to be used"
  default     = "Standard_D2s_v3"
}

variable "hide_session_launch_password" {
  type        = number
  description = "Indicating whether session launch password will be hidden in the powershell console after deployment"
  default     = 0

  validation {
    condition     = contains([0, 1], var.hide_session_launch_password)
    error_message = "The hide_session_launch_password can only be 0 or 1. 0 for False and 1 for True."
  }
}

################################################################################
#                                                                              #
#                            Azure VNet Settings                               #
#                                                                              #
################################################################################
variable "ad_dns_prefix" {
  type        = string
  description = "DNS prefix for AD VM configuration"
  default     = null
}

variable "ad_vnet_address_space" {
  type    = string
  default = "10.0.0.0/16"
}

variable "ad_vnet_address_prefix" {
  type    = string
  default = "10.0.0.0/24"
}

################################################################################
#                                                                              #
#                             Azure AD VM Settings                             #
#                                                                              #
################################################################################

variable "advm_machine_name" {
  type        = string
  description = "Machine Name for Active Directory VM"
  default     = "ctx-adVM"
  validation {
    condition     = length(var.advm_machine_name) <= 15
    error_message = "Name of the Active Directory VM can be at most 15 characters long."
  }
}

variable "advm_admin_username" {
  type        = string
  description = "Administrator username for the AD VM"

  default = "advmadmin"
}

variable "advm_admin_password" {
  type        = string
  description = "Admin password of the AD VM"
  sensitive   = true

  default = ""
  validation {
    condition = var.advm_admin_password == "" || alltrue([can(regex("[0-9]+", var.advm_admin_password)), 
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

  default = "ctx-ad.local"
}

variable "ad_private_ip_addr" {
  type        = string
  description = "Private IP address for the AD domain controller VM"
  default     = "10.0.0.4"
}

variable "ad_ip_config_name" {
  type        = string
  description = "AD domain controller VM ip configuration name"
  default     = "internal"
}

variable "ad_usergroup_name" {
  type        = string
  description = "AD user group name"
  default     = "CtxUserGroup"
}

variable "ad_ou_name" {
  type        = string
  description = "AD Organization Unit name"
  default     = "CtxOU"
}

variable "vnet_rdp_source_ips" {
  type        = list(any)
  description = "Comma separated list of IP Addresses to whitelist for RDP access in the VNet. Individual tags such as VirtualNetwork, AzureLoadBalancer and Internet can also be used. Asterisk (*) can be used to allow any source."
  # Empty list disables RDP access. Use ["*"] to allow any source.
  default = ["*"]
}

variable "ad_default_user_password" {
  type        = string
  description = "Password for the default users added to the Active Directory."
  sensitive   = true
  default     = ""

  validation {
    condition = var.ad_default_user_password == "" || alltrue([can(regex("[0-9]+", var.ad_default_user_password)), 
                         can(regex("[A-Z]+", var.ad_default_user_password)), 
                         can(regex("[a-z]+", var.ad_default_user_password)), 
                         can(regex("[^0-9A-Za-z]+", var.ad_default_user_password)),
                         length(var.ad_default_user_password) >= 8])
    error_message = "Variable ad_default_user_password must satisfy the following conditions: 1. At least 8 characters; 2. At least 1 upper case letter; 3. At least 1 lower case letter; 4. At least 1 special character; 5. At least 1 numerical character."
  }
}

################################################################################
#                                                                              #
#                             Azure DDC Settings                               #
#                                                                              #
################################################################################

variable "cvad_installer_iso_file_path" {
  type        = string
  description = "Path of the local CVAD installer iso file."
}

variable "ddc_machine_name" {
  type        = string
  description = "Machine Name for DDC VM"
}

variable "ddc_private_ip_addr" {
  type        = string
  description = "Private IP address for the AD domain controller VM"
  default     = "10.0.0.5"
}

variable "ddc_dns_prefix" {
  type        = string
  description = "DNS prefix for DDC VM"
  default     = null
}

variable "ddc_admin_username" {
  type        = string
  description = "Administrator username for the DDC VM"
  default     = "ddcAdmin"
}

variable "ddc_admin_password" {
  type        = string
  description = "Admin password of the DDC VM"
  sensitive   = true
  default     = ""
  
  validation {
    condition = var.ddc_admin_password == "" || alltrue([can(regex("[0-9]+", var.ddc_admin_password)), 
                         can(regex("[A-Z]+", var.ddc_admin_password)), 
                         can(regex("[a-z]+", var.ddc_admin_password)), 
                         can(regex("[^0-9A-Za-z]+", var.ddc_admin_password)),
                         length(var.ddc_admin_password) >= 8])
    error_message = "Variable ddc_admin_password must satisfy the following conditions: 1. At least 8 characters; 2. At least 1 upper case letter; 3. At least 1 lower case letter; 4. At least 1 special character; 5. At least 1 numerical character."
  }
}

variable "ddc_vm_size_sku" {
  type        = string
  description = "Azure VM Size SKU for DDC"

  default = "Standard_D4as_v4"
}

variable "ddc_site_name" {
  type        = string
  description = "Name of the site"
  default     = "ctx"
}

variable "ddc_cvad_components" {
  type        = string
  description = "components installed on ddc vm"
  #TODO: selection for external or internal components inside DDC machine
  default = "CONTROLLER,DESKTOPSTUDIO,WEBSTUDIO,DESKTOPDIRECTOR,LICENSESERVER"
}

variable "citrix_modules_path" {
  type        = string
  description = "Path in the DDC VM where the citrix files will be stored"
  default     = "C:/CitrixModules"
}

variable "store_virtual_path" {
  type        = string
  description = "Virtual path for storefront store. Paths for storefront authentication service and receiver are determined based on store path."
  default     = "/Citrix/Store"
}

variable "storefront_delivery_controller_port" {
  type        = number
  description = "Port for Delivery Controller"
  default     = 443

  validation {
    condition     = contains([80, 443], var.storefront_delivery_controller_port)
    error_message = "The storefront_delivery_controller_port variable value can only be 80 or 443. Value 80 for Http and 443 for Https."
  }
}

variable "farmType" {
  type        = string
  description = "Type of Delivery Controller Server farm. E.g. XenDesktop or XenApp"
  default     = "XenDesktop"
}

variable "farmName" {
  type        = string
  description = "Name for the Delivery Controller Server farm"
  default     = "CVAD-DeliveryController"
}

variable "are_ddc_servers_load_balanced" {
  type        = bool
  description = "Flag to specify if Delivery Controller Servers are load balanced or not. This can be set to true even for a single delivery controller server."
  default     = true
}

variable "storefront_store_friendly_name" {
  type        = string
  description = "Display name for the store front store"
  default     = "ctx-store"
}

################################################################################
#                                                                              #
#                          License Server Settings                             #
#                                                                              #
################################################################################

variable "license_server_address" {
  type        = string
  description = "IP address of the license server"
  default     = ""
}

variable "license_server_port" {
  type        = number
  description = "Port for the license server"
  default     = 27000
}

variable "product_code" {
  type        = string
  description = "Product Code for the License Server"
  default     = "XDT"
}

variable "product_edition" {
  type        = string
  description = "Product Edition for the License Server"
  default     = "PLT"
}

variable "license_file_path" {
  type        = string
  description = "Path of the license file"
  default = ""
}

################################################################################
#                                                                              #
#                             SQL Server Settings                              #
#                                                                              #
################################################################################

variable "setup_independent_sql_vm" {
  type        = bool
  description = "Indicates whether SQL Server is installed in a separate VM or within the DDC VM"
  default     = false
}

variable "mssql_machine_name" {
  type        = string
  description = "Machine Name for MSSQL VM"
  default     = "ctx-mssql"
  validation {
    condition     = length(var.mssql_machine_name) <= 15
    error_message = "Name of the MSSQL VM can be at most 15 characters long."
  }
}

variable "mssql_private_ip_addr" {
  type        = string
  description = "Private IP address for the MSSQL VM"
  default     = "10.0.0.6"
}

variable "mssql_admin_username" {
  type        = string
  description = "Admin Username for the MSSQL VM"
  default     = "sqlVmAdmin"
}

variable "mssql_admin_password" {
  type        = string
  description = "Admin Password for the MSSQL VM"
  sensitive   = true

  default = ""

  validation {
    condition = var.mssql_admin_password == "" || alltrue([can(regex("[0-9]+", var.mssql_admin_password)), 
                         can(regex("[A-Z]+", var.mssql_admin_password)), 
                         can(regex("[a-z]+", var.mssql_admin_password)), 
                         can(regex("[^0-9A-Za-z]+", var.mssql_admin_password)),
                         length(var.mssql_admin_password) >= 8])
    error_message = "Variable mssql_admin_password must satisfy the following conditions: 1. At least 8 characters; 2. At least 1 upper case letter; 3. At least 1 lower case letter; 4. At least 1 special character; 5. At least 1 numerical character."
  }
}

variable "mssql_vm_sku" {
  type        = string
  description = "Sku for VM hosting the Microsoft sql server."
  default     = "standard-gen2"

  validation {
    condition     = contains(["standard-gen2", "enterprise-gen2"], var.mssql_vm_sku)
    error_message = "The mssql_vm_sku value can only be 'standard-gen2' or 'enterprise-gen2'."
  }
}

variable "sql_connectivity_username" {
  type        = string
  description = "Username to connect to sql database"
  default     = "sqlServerAdmin"
}

variable "sql_connectivity_password" {
  type        = string
  description = "Password to connect to sql database"
  sensitive   = true
  default     = ""

  validation {
    condition = var.sql_connectivity_password == "" || alltrue([can(regex("[0-9]+", var.sql_connectivity_password)), 
                         can(regex("[A-Z]+", var.sql_connectivity_password)), 
                         can(regex("[a-z]+", var.sql_connectivity_password)), 
                         can(regex("[^0-9A-Za-z]+", var.sql_connectivity_password)),
                         length(var.sql_connectivity_password) >= 8])
    error_message = "Variable sql_connectivity_password must satisfy the following conditions: 1. At least 8 characters; 2. At least 1 upper case letter; 3. At least 1 lower case letter; 4. At least 1 special character; 5. At least 1 numerical character."
  }
}

################################################################################
#                                                                              #
#                          External Store Front Settings                       #
#                                                                              #
################################################################################

variable "storefront_username" {
  type        = string
  description = "Username for the storefront server"
  default     = "storeFrontAdmin"
}

variable "storefront_password" {
  type        = string
  description = "Password for the storefront server"
  sensitive   = true

  default = ""

  validation {
    condition = var.storefront_password == "" || alltrue([can(regex("[0-9]+", var.storefront_password)), 
                         can(regex("[A-Z]+", var.storefront_password)), 
                         can(regex("[a-z]+", var.storefront_password)), 
                         can(regex("[^0-9A-Za-z]+", var.storefront_password)),
                         length(var.storefront_password) >= 8])
    error_message = "Variable storefront_password must satisfy the following conditions: 1. At least 8 characters; 2. At least 1 upper case letter; 3. At least 1 lower case letter; 4. At least 1 special character; 5. At least 1 numerical character."
  }
}

variable "storefront_vm_count" {
  type        = number
  description = "External StoreFront VM name"
  default     = 0
  validation {
    condition     = floor(var.storefront_vm_count) == var.storefront_vm_count && var.storefront_vm_count >= 0
    error_message = "The number of independent Storefront can be >= 0"
  }
}

variable "storefront_machine_name" {
  type        = string
  description = "Machine Name for Storefront VM"
  default     = "ctx-sf"
  validation {
    condition     = length(var.storefront_machine_name) <= 15
    error_message = "Name of the StoreFront VM can be at most 15 characters long."
  }
}

################################################################################
#                                                                              #
#                          Machine Creation Settings                           #
#                                                                              #
################################################################################

variable "machine_catalog_name" {
  type        = string
  description = "Name of Machine Catalog Created for User"
  default     = "Ctx-Machine-Catalog"
}

variable "catalog_session_support" {
  type        = string
  description = "Session support type of the Machine Catalog created for the user"
  # If license file is not provided, only single session catalog is supported
  default     = "MultiSession"
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

variable "persist_user_changes" {
  type        = string
  description = "Whether user changes will be kept for Machine Catalog"
  default     = "Discard"

  validation {
    condition     = contains(["Discard", "OnLocal"], var.persist_user_changes)
    error_message = "The machine catalog user change persistence option can only be Discard or OnLocal."
  }
}
variable "delivery_group_name" {
  type        = string
  description = "Name of Delivery Group Created for User"
  default     = "CtxDeliveryGroup"
}

variable "ddc_connection_name" {
  type        = string
  description = "Name for Hypervisor Connection"
  default     = "CtxAzureConnection"
}

variable "ddc_hosting_unit_name" {
  type        = string
  description = "Name for Hypervisor Hosting Unit"
  default     = "CtxAzureHosting"
}

variable "access_policy_user" {
  type        = string
  description = "Name for Access Policy for Delivery Group"
  default     = "CtxAccessPolicy"
}

variable "desktop_entitle_rule" {
  type        = string
  description = "Name for Desktop Entitlement Rule"
  default     = "CtxDesktopRule"
}

variable "desktop_name" {
  type        = string
  description = "Name for Desktop Created"
  default     = "CtxDesktop"
}

################################################################################
#                                                                              #
#                             Director Settings                                #
#                                                                              #
################################################################################

variable "director_username" {
  type        = string
  description = "Username for the director server"
  default     = "directorAdmin"
}

variable "director_password" {
  type        = string
  description = "Password for the director server"
  sensitive   = true
  default     = ""

  validation {
    condition = var.director_password == "" || alltrue([can(regex("[0-9]+", var.director_password)), 
                         can(regex("[A-Z]+", var.director_password)), 
                         can(regex("[a-z]+", var.director_password)), 
                         can(regex("[^0-9A-Za-z]+", var.director_password)),
                         length(var.director_password) >= 8])
    error_message = "Variable director_password must satisfy the following conditions: 1. At least 8 characters; 2. At least 1 upper case letter; 3. At least 1 lower case letter; 4. At least 1 special character; 5. At least 1 numerical character."
  }
}

variable "director_count" {
  type        = number
  description = "External Director Count"
  default     = 0
  validation {
    condition     = contains([0, 1], var.director_count)
    error_message = "The number of independent Director can only be 0 or 1"
  }
}

variable "director_machine_name" {
  type        = string
  description = "Machine Name for Director VM"
  default     = "ctx-dir"
  validation {
    condition     = length(var.director_machine_name) <= 15
    error_message = "Name of the Director VM can be at most 15 characters long."
  }
}

################################################################################
#                                                                              #  
#                        Standalone Web Studio Settings                        #
#                                                                              #
################################################################################

variable "webstudio_username" {
  type        = string
  description = "Username for the web studio server"
  default     = "webstudioAdmin"
}

variable "webstudio_password" {
  type        = string
  description = "Password for the web studio server"
  sensitive   = true
  default     = ""

  validation {
    condition = var.webstudio_password == "" || alltrue([can(regex("[0-9]+", var.webstudio_password)), 
                         can(regex("[A-Z]+", var.webstudio_password)), 
                         can(regex("[a-z]+", var.webstudio_password)), 
                         can(regex("[^0-9A-Za-z]+", var.webstudio_password)),
                         length(var.webstudio_password) >= 8])
    error_message = "Variable webstudio_password must satisfy the following conditions: 1. At least 8 characters; 2. At least 1 upper case letter; 3. At least 1 lower case letter; 4. At least 1 special character; 5. At least 1 numerical character."
  }
}

variable "webstudio_count" {
  type        = number
  description = "Number of independent webstudio server"
  default     = 0
  validation {
    condition     = contains([0, 1], var.webstudio_count)
    error_message = "The number of independent Webstudio can only be 0 or 1"
  }
}

variable "webstudio_machine_name" {
  type        = string
  description = "Machine Name for Webstudio VM"
  default     = "ctx-web"
  validation {
    condition     = length(var.webstudio_machine_name) <= 15
    error_message = "Name of the WebStudio VM can be at most 15 characters long."
  }
}

################################################################################
#                                                                              #  
#                       Virtual Delivery Agent Settings                        #
#                                                                              #
################################################################################

variable "vda_machine_count" {
  type        = number
  description = "Number of Machine Created"
  default     = 2

  validation {
    condition     = floor(var.vda_machine_count) == var.vda_machine_count && var.vda_machine_count >= 0
    error_message = "The number of VDAs could only be an integer with value greater or equals to 0."
  }
}

variable "vda_machine_name" {
  type        = string
  description = "Machine Name for VDA VM"
  default     = "ctx-vda"
  validation {
    condition     = length(var.vda_machine_name) <= 15
    error_message = "Name of the VDA VM(s) can be at most 15 characters long."
  }
}

variable "vda_username" {
  type        = string
  description = "Username for the VDA VM"
  default     = "vdaAdmin"
}

variable "vda_password" {
  type        = string
  description = "Password for the VDA VM"
  sensitive   = true
  default     = ""

  validation {
    condition = var.vda_password == "" || alltrue([can(regex("[0-9]+", var.vda_password)), 
                         can(regex("[A-Z]+", var.vda_password)), 
                         can(regex("[a-z]+", var.vda_password)), 
                         can(regex("[^0-9A-Za-z]+", var.vda_password)),
                         length(var.vda_password) >= 8])
    error_message = "Variable must satisfy the following conditions: 1. At least 8 characters; 2. At least 1 upper case letter; 3. At least 1 lower case letter; 4. At least 1 special character; 5. At least 1 numerical character."
  }
}
