# Site Deployment Module for Citrix® Virtual Apps and Desktops
The Site Deployment Module for Citrix® Virtual Apps and Desktops aims to provide a simplified way to deploy a functional site. This module also offers flexibility and options to customize the site. A single command can be used to deploy the entire site without worrying about all of the technical details.

## Environment Requirement
1. PowerShell with version `5.0` or higher
2. PowerShell `Az` module with version `9.0.0` or higher
3. Terraform with version `1.1.0` or higher

## Deployment
1. Make a copy of the `azure.tfvars.json.example` and the `inputs.tfvars.json.example` files. Then rename the new files to `azure.tfvars.json` and `inputs.tfvars.json` respectively
2. Review and customize the input variable values in `inputs.tfvars.json` to make sure that the parameters are set to desired values. For input value descriptions, you may find them in `/terraform/variables.tf` file.
3. Set CVAD installer ISO file path variables:
   - If you have CVAD installer locally, please set `cvad_installer_iso_file_path` variable to the full path to local CVAD installer and set `is_cvad_installer_stored_locally` to `true`. 
   - If you don't have the CVAD installer locally, please set `is_cvad_installer_stored_locally` variable to `false`, set `cvad_installer_iso_file_path` variable to the URL of the CVAD installer, and set `cvad_installer_iso_file_md5` to the installer ISO file's MD5 value
4. Please open a PowerShell session with **Administrator privilege**
5. Run the following command in the PowerShell session to set the execution policy

> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`   

6. Run `New-ActiveDirectoryAppRegistration.ps1` script with the required `AzureSubscriptionId` parameter, the optional `AzureTenantId` parameter, and the optional `AzureApplicationName` to create an Azure App Registration for Citrix Virtual Apps and Desktops (CVAD) deployment

> `./New-ActiveDirectoryAppRegistration.ps1 -AzureSubscriptionId <Your Azure Subscription Id> [-AzureTenantId <Your Azure Subscription Tenant Id>] [-AzureApplicationName <Your New Azure App Registration Name>]`

7. Run the `New-CvadDeployment.ps1` script with the optional `-AutoApprove` flag for skipping Terraform plan verification to complete the deployment. You may also add the `-PreserveAzureCredential` flag to save Azure credential in `azure.tfvars.json` file, if this flag is not specified, the Azure credential will be removed once the deployment completed. The optional `-ShowSessionLaunchPassword` argument may be added to show passwords for session launch or site management. **The `-ShowSessionLaunchPassword` flag should only be added if it is safe to store credentials in the package folder.**

> `./New-CvadDeployment.ps1 [-AutoApprove] [-PreserveAzureCredential] [-ShowSessionLaunchPassword]`

## Deployment Removal
1. Make sure you are using the **same environment** that used for the deployment
2. Please open a PowerShell session with **Administrator privilege**
3. Please run the following command in the PowerShell session to set the execution policy

> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`   

1. Run the `Remove-CvadDeployment.ps1` script for resource deletion. The optional `AutoApprove` flag can be added for skipping Terraform plan verification. You may also add the `-PreserveAzureCredential` flag to save Azure credential in `azure.tfvars.json` file, if this flag is not specified, the Azure credential will be removed once the deployment completed.

> `./Remove-CvadDeployment.ps1 [-AutoApprove] [-PreserveAzureCredential]`

# Attributions
The code in this repository makes use of the following packages:
- Hashicorp Terraform (https://github.com/hashicorp/terraform)
- Plugin for Terraform Provider for Citrix® (https://github.com/citrix/terraform-provider-citrix)
- Terraform Provider Archive (https://github.com/hashicorp/terraform-provider-archive)
- Terraform Provider for Azure (https://github.com/hashicorp/terraform-provider-azurerm)
- Terraform Provider: Local (https://github.com/hashicorp/terraform-provider-local)
- Terraform Provider Random (https://github.com/hashicorp/terraform-provider-random)


# License 
This project is Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

<sub>Copyright © 2023. Citrix Systems, Inc. All Rights Reserved.</sub>
