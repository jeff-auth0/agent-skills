# auth0-terraform

Reverse-engineers an active Auth0 tenant into a clean, multi-environment Terraform project ready to replicate that tenant into new empty tenants.

## What it does

1. Runs `auth0 tf generate` against your active tenant
2. Transforms the flat output into a structured project:
   - `modules/` — one `for_each` block per resource type
   - `envs/` — per-environment directories (populated + skeleton stubs)
   - `secrets.tf` — comment scaffolds for secret injection (choose Azure KV, AWS SM, GitHub Actions, or env vars)
   - `.gitignore`, `PROJECT_CONTEXT.md`, `CLAUDE.md`
3. Optionally generates a CI/CD pipeline as a separate step (`azure-pipelines` supported)

## Install

```bash
npx skills add jeff-auth0/agent-skills@auth0-terraform -g
```

## Usage

Invoke the skill in Claude Code:

```
generate terraform for my auth0 tenant
```

or

```
reverse engineer auth0 to terraform
```

The agent will:
- Confirm the active tenant
- Ask for credentials securely (env file recommended — secret never enters transcript)
- Ask 4 questions: environment name, other envs to scaffold, state backend, output path
- Generate the project, validate it, and write a `PROJECT_CONTEXT.md` for continuity
- Optionally generate a CI/CD pipeline as a follow-up step

## Prerequisites

- [Auth0 CLI](https://github.com/auth0/auth0-cli) — `brew install auth0`
- Terraform — `brew install terraform`
- Python 3 with `python-hcl2` (auto-installed by skill if missing)
- A **Machine-to-Machine app** in Auth0 Dashboard authorized on the Management API with `read:*` scopes

## Generated project structure

```
auth0-terraform/
├── modules/
│   ├── applications.tf
│   ├── actions.tf
│   ├── connections.tf
│   └── ...                   # one file per resource type
├── envs/
│   ├── dev/                  # populated from active tenant
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── terraform.tfvars
│   │   └── secrets.tf        # injection scaffolds
│   ├── preprod/              # empty skeleton
│   └── prod/                 # empty skeleton
├── azure-pipelines.yml       # if azure-pipelines selected
├── .gitignore
├── PROJECT_CONTEXT.md
└── CLAUDE.md
```

## Secrets wiring

`secrets.tf` in each populated env contains ready-to-use comment templates for wiring external secrets (social connection keys, action secrets, email provider credentials).

Choose your approach:

| Approach | How |
|---|---|
| Azure Key Vault | Uncomment `azurerm_key_vault_secret` data source blocks in `secrets.tf` |
| AWS Secrets Manager | Uncomment `aws_secretsmanager_secret_version` data source blocks in `secrets.tf` |
| GitHub Actions | Set `TF_VAR_<type>_secrets` env vars in your workflow (template in `secrets.tf`) |
| Any CI / local | `export TF_VAR_<type>_secrets='{"key":"value"}'` |

Auth0-generated secrets (client secrets, signing keys) stay in Terraform state — no injection needed.

## What is not replicated

- Built-in Auth0 resource servers (Management API, My Account API) — auto-provisioned by every tenant
- Auth0-generated secrets (client_id, client_secret, signing_keys) — stay in Terraform state, not injected
