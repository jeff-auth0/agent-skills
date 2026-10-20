# auth0-terraform

Reverse-engineers an active Auth0 tenant into a clean, multi-environment Terraform project, ready to replicate that tenant into new empty tenants.

The skill **exports, modularizes and documents**. It does not wire secrets to a vault, generate CI/CD pipelines or choose a state backend. Those belong to the customer, and the generated README says exactly what they need.

## What it does

1. Runs `auth0 tf generate` against your active tenant.
2. Transforms the flat output into a structured project:
   - `modules/`: one `for_each` block per resource type, plus extracted action code, email templates and login page.
   - `envs/`: one directory per environment (one populated from the tenant, the rest empty skeletons).
   - `secrets`: a single variable holding every customer-supplied value, with `modules/secrets.tf` failing the plan with a list of any missing keys.
   - `README.md`: prerequisites, getting started, and **the full list of secret keys the customer must supply**.
   - `.gitignore`, `PROJECT_CONTEXT.md`, `CLAUDE.md`.
3. Later, **resyncs** dashboard changes into the project without losing the customer's own edits (see below).

## Install

```bash
npx skills add jeff-auth0/agent-skills@auth0-terraform -g
```

## Usage

Invoke the skill in Claude Code:

```
generate terraform for my auth0 tenant
```

The agent will:
- Confirm the active tenant.
- Ask for credentials in a way that keeps the secret out of the transcript (an env file is recommended).
- Ask three questions: environment name, other environments to scaffold, output path.
- Generate the project, validate it, and write a `PROJECT_CONTEXT.md` for continuity.

## Prerequisites

- [Auth0 CLI](https://github.com/auth0/auth0-cli): `brew install auth0`
- **Terraform 1.11 or later**: `brew install terraform`. The Auth0 provider uses write-only attributes. The older `terraform` binary the Auth0 CLI bundles cannot validate the generated project.
- Python 3 with `python-hcl2` (installed by the skill if missing)
- A **Machine-to-Machine app** authorized on the Management API with `read:*` scopes (the export only reads)

## Generated project

```text
<out>/
├── modules/
│   ├── secrets.tf              the `secrets` variable and the required-keys check
│   ├── applications.tf         one file per resource type
│   ├── actions.tf
│   ├── connections.tf
│   ├── variables.tf
│   └── code/                   extracted action code, email templates, login page
├── envs/
│   ├── dev/                    populated from the exported tenant
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── terraform.tfvars    non-secret configuration
│   │   ├── secrets.tf
│   │   ├── providers.tf
│   │   └── backend.tf          neutral stub; the customer configures state
│   ├── test/                   empty skeleton
│   └── prod/                   empty skeleton
├── README.md                   customer-facing guide, including every required secret key
├── .auth0tf/                   baseline used by resync (commit it)
├── .gitignore
├── PROJECT_CONTEXT.md
└── CLAUDE.md
```

## Secrets

Auth0 never returns secret values, so none are stored in the project. Everything the customer must supply goes through **one variable**, `secrets`: a flat `map(string)`.

```json
{
  "email_provider.api_key": "...",
  "actions.my_action.API_KEY": "...",
  "connections.my_db.configuration.base_uri": "..."
}
```

Keys are `<variable>.<resource key>.<name>`; the resource key is omitted for singletons such as the email provider.

- The generated `README.md` lists **every** key for the exported tenant. It is built from the same data as the Terraform, so the two cannot disagree.
- With keys missing, `terraform plan` stops with one message listing all of them.
- **How the map is filled is the customer's responsibility.** `TF_VAR_secrets` (a JSON object) and a gitignored `secrets.auto.tfvars.json` both work; any vault or CI system can build either. The skill generates no vendor-specific wiring.
- Which values count as secrets comes from an explicit table (`secrets.py`) derived from the provider schema, not from field names. Sensitive settings the export cannot reveal (addons, CAPTCHA keys, push MFA) are listed in the README for the customer to add by hand.
- Auth0-generated secrets (client secrets, signing keys) are created on apply and kept in Terraform state. The customer never supplies them.

## Resync

When the tenant is changed in the dashboard, pull just those changes into the existing project:

```bash
python3 -m scripts.auth0tf.cli resync --input /tmp/auth0tf-raw --project <dir> --env dev --dry-run
```

- Each managed file is merged three ways: **baseline** (what was generated last time, stored in `.auth0tf/`), **tenant** (generated now) and **project** (on disk). Customer edits survive; overlapping edits become conflict markers.
- Only `modules/`, `envs/<env>/` and `README.md` change. Other environments, `backend.tf`, `.gitignore` and files you added are never touched.
- Works on a new branch (`auth0/resync`), commits there and **never pushes**.
- The report lists `+ added`, `~ changed` and `- removed` resources (with a **destroy warning** for removals) and any **newly required secret keys**.
- Refuses, changing nothing, when there is no baseline, the env is wrong, the project is not a git repo or managed files have uncommitted changes. Projects exported before resync existed need a re-export.

Limits: a rename looks like a removal plus an addition; secret values are never seen.

## What is not replicated

- Built-in Auth0 resource servers (Management API, My Account API), auto-provisioned by every tenant.
- Auth0-generated secrets and identifiers (client IDs, client secrets, signing keys).

## What the customer owns

State backend, secret storage and injection, CI/CD, and per-environment values (custom domain, identifiers). The generated README covers each.

## Development

```bash
python3 -m venv venv && venv/bin/pip install -e '.[dev]'
venv/bin/python -m pytest
```

Tests that run `terraform` are skipped when it is not installed.
