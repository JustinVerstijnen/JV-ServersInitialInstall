# JV Azure Domain Controller Terraform Deployment

This project deploys a Windows Server VM in Azure and promotes it to a new Active Directory Domain Controller.

The PowerShell bootstrap script is downloaded by the Azure Custom Script Extension from a public GitHub raw URL. No Azure Storage Account is created for the script in this version.

## Project structure

```text
jv-azure-dc-terraform/
├── .vscode/
│   └── tasks.json
├── scripts/
│   └── bootstrap-dc.ps1
├── .gitignore
├── locals.tf
├── main.tf
├── outputs.tf
├── terraform.tfvars.example
├── variables.tf
└── versions.tf
```

## What it creates

Based on the `project` variable, Terraform creates resources with this naming convention:

```text
Resource group: rg-jv-<project>
VM:             vm-jv-<project>
OS disk:        osdisk-jv-<project>
VNET:           vnet-jv-<project>
NIC:            nic-jv-<project>
Public IP:      pip-jv-<project>
NSG:            nsg-jv-<project>
```

Default AD forest name:

```text
internal.justinverstijnen.nl
```

Default internal IP:

```text
10.69.0.4
```

## GitHub script hosting

1. Create a public GitHub repository.
2. Upload this file to the repository:

```text
scripts/bootstrap-dc.ps1
```

3. Open the file in GitHub.
4. Click **Raw**.
5. Copy the raw URL.
6. Paste it in `terraform.tfvars`:

```hcl
bootstrap_script_url = "https://raw.githubusercontent.com/<owner>/<repo>/main/scripts/bootstrap-dc.ps1"
```

Keep this value aligned with the actual file name:

```hcl
bootstrap_script_file_name = "bootstrap-dc.ps1"
```

When you change the script after a deployment and want the Custom Script Extension to run again, increase this value:

```hcl
bootstrap_script_version = "2"
```

For first-time deployment this does not matter; the extension runs during VM creation.

## RDP source IP allow list

RDP is not opened to the entire internet by default. Configure the allowed source IP addresses in `terraform.tfvars`:

```hcl
rdp_source_address_prefixes = ["203.0.113.10/32", "203.0.113.11/32"]
```

For a single public IP address:

```hcl
rdp_source_address_prefixes = ["203.0.113.10/32"]
```

Temporary lab-only option:

```hcl
rdp_source_address_prefixes = ["*"]
```

## Requirements

Install these tools on your workstation:

- Visual Studio Code
- Terraform CLI
- Azure CLI
- HashiCorp Terraform extension for Visual Studio Code

## How to run from Visual Studio Code

1. Extract this ZIP file.
2. Open the extracted folder in Visual Studio Code.
3. Copy `terraform.tfvars.example` to `terraform.tfvars`.
4. Edit `terraform.tfvars` and fill in:
   - `subscription_id`
   - `admin_password`
   - `safe_mode_password`
   - `bootstrap_script_url`
   - `rdp_source_address_prefixes`
5. Open a terminal in Visual Studio Code.
6. Sign in to Azure:

```powershell
az login
```

7. Optional: set the correct subscription:

```powershell
az account set --subscription "00000000-0000-0000-0000-000000000000"
```

8. Initialize Terraform:

```powershell
terraform init
```

9. Format and validate:

```powershell
terraform fmt -recursive
terraform validate
```

10. Create a deployment plan:

```powershell
terraform plan -out main.tfplan
```

11. Apply the deployment:

```powershell
terraform apply main.tfplan
```

## VS Code tasks

This ZIP contains `.vscode/tasks.json` with tasks for:

- Terraform Init
- Terraform Format
- Terraform Validate
- Terraform Plan
- Terraform Apply
- Terraform Destroy

In VS Code, open the Command Palette and run:

```text
Tasks: Run Task
```

Then select the Terraform task you want to run.

## Logs on the deployed server

After deployment, check this folder on the VM:

```text
C:\JV-Install\
```

The bootstrap script creates a scheduled task named:

```text
JV-Promote-DC
```

The scheduled task performs the AD DS installation and domain controller promotion. Terraform may finish before the scheduled task and reboot are fully completed, so give the VM some time before testing RDP or Active Directory.

## Destroy the lab environment

When you are done testing:

```powershell
terraform destroy
```

## Security note

The values `admin_password` and `safe_mode_password` are marked as sensitive in Terraform, but they can still end up in Terraform state files and plan files. Do not commit `terraform.tfvars`, `.tfstate`, or `.tfplan` files to Git.

For production usage, use a secure approach such as Azure Key Vault, secure pipeline variables, and a protected remote Terraform backend.
