# auth0-terraform

Reverse-engineers an active Auth0 tenant into a clean, multi-environment Terraform project ready to replicate that tenant into new empty tenants.

## What it does

1. Runs `auth0 tf generate` against your active tenant
2. Transforms the flat output into a structured project:
   - `modules/` — one `for_each` block per resource type
   - `envs/` — per-environment directories (populated + skeleton stubs)
   - `.gitignore` — pre-configured for Terraform + secrets
   - `PROJECT_CONTEXT.md` + `CLAUDE.md` — session continuity for future agents
3. Optionally generates an Azure DevOps pipeline with Key Vault secret injection (`azure-pipelines` only — GitHub Actions and GitLab CI not yet supported)

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
- Ask 4 questions: environment name, KV provider (`azure` only), other envs to scaffold, CI/CD pipeline (`azure-pipelines` or `none`)
- Generate the project, validate it, and write a `PROJECT_CONTEXT.md` for continuity

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
│   │   └── terraform.tfvars
│   ├── preprod/              # empty skeleton
│   └── prod/                 # empty skeleton
├── azure-pipelines.yml       # if azure-pipelines selected
├── .gitignore
├── PROJECT_CONTEXT.md
└── CLAUDE.md
```

## Azure Pipelines — secret wiring

The generated pipeline injects secrets from per-environment Key Vaults via `AzureKeyVault@2`.

**Variable group** — env-agnostic values only:

| Variable | Description |
|---|---|
| `azureServiceConnection` | Azure DevOps service connection name |
| `kvName<Env>` | Key Vault name for each environment (one entry per env) |

**Each env's Key Vault** — minimum required secrets:

| Secret name | Terraform variable |
|---|---|
| `auth0-domain` | `TF_VAR_auth0_domain` |
| `auth0-client-id` | `TF_VAR_auth0_client_id` |
| `auth0-client-secret` | `TF_VAR_auth0_client_secret` |

Add any additional secrets your modules require (e.g. email provider credentials, custom connection keys) to each env's vault and inject them as `TF_VAR_*` in the pipeline.

> `auth0-domain` is per-environment — it must live in Key Vault, never in the shared variable group.

## What is not replicated

- Built-in Auth0 resource servers (Management API, My Account API) — auto-provisioned by every tenant
- Auth0-generated secrets (client secrets, signing keys) — appear as outputs to push into KV after first apply
