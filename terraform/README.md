# JV Azure Domain Controller Terraform Deployment

This project deploys a Windows Server VM in Azure and promotes it to a new Active Directory Domain Controller.

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
```

Default AD forest name:

```text
internal.justinverstijnen.nl
```

Default internal IP:

```text
10.69.0.4
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
   - `rdp_source_address_prefix`
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
