# Quick Start Guide
## Environment Requirement
1. PowerShell with version `5.0` or higher
2. PowerShell `Az` module with version `9.0.0` or higher
3. Terraform with version `1.1.0` or higher

## Deployment
1. Please open a PowerShell session with **Administrator priviledge**
2. Run the following command in the PowerShell session to set execution policy

> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`   

3. Run `New-ActiveDirectoryAppRegistration.ps1` script with the required `AzureSubscriptionId` parameter and optional `AzureApplicationName` to create an Azure App Registration for Citrix Virtual Apps and Desktops (CVAD) deployment

> `./New-ActiveDirectoryAppRegistration.ps1 -AzureSubscriptionId <Your Azure Subscription Id> [-AzureApplicationName <Your New Azure App Registration Name>]`

4. Review `inputs.tfvars` and the default values in `\terraform\variables.tf` to make sure that the parameters are set to desired values
5. Run `Start-CvadDeployment.ps1` script with optional `AutoApprove` flag for skipping Terraform plan verification to complete deployment

> `./Start-CvadDeployment.ps1 [-AutoApprove]`

## Deployment Removal
1. Make sure you are using the same envionment that used for deployment
2. Please open a PowerShell session with **Administrator priviledge**
3. Please run the following command in PowerShell session to set execution policy

> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`   

1. Run `Start-CvadDeployment.ps1` script with `Destroy` flag for resource deletion. The optional `AutoApprove` flag can be added for skipping Terraform plan verification

> `./Start-CvadDeployment.ps1 -Destroy [-AutoApprove]`

# Attributions
The code in this repository makes use of the following packages:
- Hashicorp Terraform (https://github.com/hashicorp/terraform)
- Terraform Provider for Azure (https://github.com/hashicorp/terraform-provider-azurerm)


# License 
This project is Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

<sub>Copyright © 2023. Citrix Systems, Inc. All Rights Reserved.</sub>
