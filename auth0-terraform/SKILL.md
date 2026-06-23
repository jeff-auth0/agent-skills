---
name: auth0-terraform
description: Use when you want to reverse-engineer an active Auth0 tenant into a structured, multi-environment Terraform project for replicating that tenant into new empty tenants. Runs `auth0 tf generate`, then restructures the flat output into a flat `modules/` directory (one `for_each` block per resource type with typed map variables), per-environment `envs/` directories, KV-backed input secrets (Azure Key Vault or AWS Secrets Manager), computed-secret outputs, extracted action/DB-script files, and an optional Azure pipeline. Trigger on prompts like "generate terraform for my auth0 tenant", "reverse engineer auth0 to terraform", "structure my auth0 terraform".
---

# Auth0 → Terraform Project Generator

Generates a clean, multi-environment Terraform project from an active Auth0 tenant, designed to **replicate** the tenant into new, empty tenants.

## Prerequisites check

1. Run `auth0 --version`. If missing, tell the user to install the Auth0 CLI and stop.
2. Run `python -c "import hcl2"` from the skill dir. If it fails, run
   `python -m pip install -e .` in the skill directory.
3. Run `auth0 tenants list`. Show the active tenant. **Ask the user to confirm
   this is the correct tenant before continuing.** Do not proceed without confirmation.
   - If the active tenant is wrong, switch with `auth0 tenants use <domain>`.

### Terraform provider credentials (required for the export)

`auth0 tf generate` discovers resources using the CLI login session, but the
config-generation phase it runs internally (`terraform plan -generate-config-out`)
authenticates as the **Auth0 Terraform provider**, which reads credentials from
environment variables. Without them the CLI prints *"Terraform provider
credentials not detected"* and never writes `auth0_generated.tf`.

Use a dedicated **Machine-to-Machine application** authorized on the **Auth0
Management API** with the full **`read:*`** scope set (the export only reads).
This is the portable path — no keychain/token extraction.

```bash
export AUTH0_DOMAIN=<tenant-domain>          # e.g. adica-dev-0.au.auth0.com
export AUTH0_CLIENT_ID=<m2m-client-id>
export AUTH0_CLIENT_SECRET=<m2m-client-secret>
unset AUTH0_API_TOKEN                         # api_token conflicts with client_id/secret
```

- Verify before exporting: `auth0 apps list` shows the M2M app; in the Dashboard
  it must be authorized on *Auth0 Management API* with the `read:*` scopes.
- Symptom of missing scopes: the export errors with
  `oauth2: "access_denied" "Unauthorized"` on read endpoints (prompts, branding,
  actions, …) and writes no config. Grant the scopes and retry.
- These are read-only credentials for export; they are NOT written into the
  generated project (each env supplies its own provider creds via tfvars/KV).

#### How to obtain the credentials from the user (do this BEFORE the four questions)

The agent's shell does not inherit env vars the user exported in their own
terminal (each command runs a fresh shell). A pasted client secret also persists
in the chat transcript. So ask the user to supply credentials via **one** of these,
in order of preference:

1. **Env file (recommended).** Ask the user to create a gitignored file, e.g.
   `/tmp/auth0tf.env`, containing:
   ```bash
   AUTH0_DOMAIN=<tenant-domain>
   AUTH0_CLIENT_ID=<m2m-client-id>
   AUTH0_CLIENT_SECRET=<m2m-client-secret>
   ```
   The skill then sources it **inside the same command** as the export (so the
   secret never enters the transcript or a persisted env):
   ```bash
   set -a; . /tmp/auth0tf-raw.env 2>/dev/null || . /tmp/auth0tf.env; set +a
   unset AUTH0_API_TOKEN
   auth0 tf generate --output-dir /tmp/auth0tf-raw
   ```
   Never `cat`/echo the file. Treat its path as the handle, not its contents.

2. **User runs the export themselves.** Give them the exact `export …` +
   `auth0 tf generate` commands (see Generate). They run it in their terminal and
   tell you when `auth0_generated.tf` exists; you then start at the transformer
   step. Keeps the secret entirely out of your context.

3. **Paste in chat (discouraged).** Only if the user explicitly accepts that the
   secret will be recorded in the transcript. If so, set the vars inline in the
   single export command and do not repeat the secret back in any message.

Ask which option they prefer; do not assume. If a complete `auth0_generated.tf`
already exists from a prior run, skip elicitation and use it.

## Ask these four questions (one message, in order)

1. Environment name for this active tenant (e.g. `dev`, `staging`, `prod`).
2. KV provider for secrets — **only `azure` (Azure Key Vault) is currently supported.**
   If the user asks about AWS Secrets Manager, tell them it is not yet implemented and
   proceed only if they confirm Azure is acceptable.
3. Other environment names to scaffold as empty skeletons (comma-separated, may be blank).
4. CI/CD pipeline — **only `azure-pipelines` is currently supported.**
   Present the options as:
   - `azure-pipelines` — generates a full pipeline with AzureKeyVault@2 secret injection
   - `none` — skip pipeline generation, wire CI/CD manually
   If the user asks for `github-actions` or `gitlab-ci`, tell them those are not yet
   supported and ask whether they want `none` instead.

## Generate

1. Run the Auth0 CLI generator into a temp dir, sourcing the credentials env file
   (Prerequisites option 1) **in the same command** so the secret stays out of the
   transcript and the fresh shell actually has the vars:
   ```bash
   rm -rf /tmp/auth0tf-raw && mkdir -p /tmp/auth0tf-raw
   set -a; . /tmp/auth0tf.env; set +a; unset AUTH0_API_TOKEN
   auth0 tf generate --output-dir /tmp/auth0tf-raw
   ```
   (If the user chose Prerequisites option 2, skip this — they produce
   `auth0_generated.tf` themselves and you start at step 2.)
   Confirm `/tmp/auth0tf-raw/auth0_generated.tf` exists and looks complete, e.g.
   `grep -c '^resource' /tmp/auth0tf-raw/auth0_generated.tf`.

   **If `auth0_generated.tf` is missing** but `auth0_import.tf` + a `terraform`
   binary are present: the CLI generated the config, then ran a verification
   `terraform plan` that fails for replication (it targets the *source* tenant's
   state) and **deleted the file on cleanup**. That plan failure is irrelevant —
   we only need the generated config. Re-run terraform directly in the output dir
   (it is already initialized by the CLI), sourcing the same credentials, which
   writes and keeps the file:
   ```bash
   cd /tmp/auth0tf-raw
   set -a; . /tmp/auth0tf.env; set +a; unset AUTH0_API_TOKEN
   ./terraform plan -generate-config-out=auth0_generated.tf
   ```
   A per-resource error after this is fine; the config is written during the plan
   graph walk. Verify the file now exists before continuing.
2. Run the transformer (from the skill directory), pointing at the raw output and
   the user's chosen output directory (default `./auth0-terraform`):
   ```bash
   python -m auth0tf.cli \
     --input /tmp/auth0tf-raw \
     --out ./auth0-terraform \
     --env <env> \
     --kv <azure|aws> \
     --other-envs "<comma,separated>" \
     --cicd <choice>
   ```
3. Write a `.gitignore` to `<out>/.gitignore`:
   ```
   # Terraform provider/plugin cache — re-downloaded by `terraform init`
   **/.terraform/*

   # Plan output files
   *.tfplan
   tfplan

   # State files (remote backend is used; never commit local state)
   *.tfstate
   *.tfstate.*
   *.tfstate.backup

   # Crash logs
   crash.log
   crash.*.log

   # Terraform CLI config overrides
   override.tf
   override.tf.json
   *_override.tf
   *_override.tf.json

   # Local variable overrides (secrets must never be committed)
   *.auto.tfvars

   # .terraform.lock.hcl is intentionally committed for provider version reproducibility

   # Local credentials / export helpers
   .env
   .env.*
   auth0tf.env
   ```
   Note: `terraform.tfvars` is **not** ignored — it contains non-secret config and
   is intentionally committed. `.terraform.lock.hcl` is **not** ignored — kept for
   provider version reproducibility.
4. If `terraform` is installed, run `terraform -chdir=auth0-terraform/envs/<env> init -backend=false`
   then `terraform validate`. Report any errors.

## Project Context File

After generation, ask the user two questions:

1. **Where to store `PROJECT_CONTEXT.md`?**
   - **(A) Inside the generated project directory** (e.g. `auth0-terraform/PROJECT_CONTEXT.md`) — colocated with the code, easiest to find
   - **(B) Parent directory** (e.g. `./PROJECT_CONTEXT.md`) — useful when the Terraform project is one sub-project of a larger repo

2. **Commit it or gitignore it?**
   - **Commit** — teammates can read the current state; shows up in git history
   - **Gitignore** — treated as a local scratchpad; each developer maintains their own

   If **gitignore**, add `PROJECT_CONTEXT.md` to the `.gitignore` in the same directory where the file will live (create the `.gitignore` if missing).

Then write `PROJECT_CONTEXT.md` to the chosen path using this template — fill in the actual values from the run:

```markdown
# Project Context — Auth0 Terraform (<tenant-domain>)

_Last updated: <date>_
_Auto-updated by agent after significant work. Keep under 150 lines — rotate old Done items to PROJECT_CONTEXT_ARCHIVE.md._

---

## Status
Terraform project generated from <tenant-domain>. Awaiting variable group population and first pipeline run.

## What's done
- Generated Terraform project from <tenant-domain> (<N> resources across <M> resource types)
- Environments scaffolded: <list>
- KV provider: <azure|aws>
- CI/CD: <pipeline type or none>

## What's in progress
- Nothing — project generated, needs pipeline/KV wiring before first apply

## Decisions made
- Secrets injected via pipeline env vars, not hardcoded in tfvars
- auth0_domain stored per-env in Key Vault (not in shared variable group)
- terraform.tfvars committed (non-secret config only)
- .terraform.lock.hcl committed (provider version reproducibility)

## Next / backlog (ordered)
1. Populate variable group with: azureServiceConnection, kvName<Env> for each environment
2. Add these secrets to each env's Key Vault:
   - auth0-domain
   - auth0-client-id
   - auth0-client-secret
   - any additional secrets required by your modules
3. Run pipeline plan stage for first env — verify expected adds (state is empty on first run)
4. Review plan output, then run apply
5. Repeat plan → apply for remaining environments

## Open questions
- (fill in any unresolved references flagged by the transformer)
```

Also create or update `CLAUDE.md` in the same directory as `PROJECT_CONTEXT.md`, adding this import at the top if not already present:

```markdown
@./PROJECT_CONTEXT.md
```

And add this agent behavior rule if not already present:

```markdown
## Agent Behavior: Auto-Update Context

After completing any significant implementation (plan step, apply, decision):
1. Update `PROJECT_CONTEXT.md` — no user prompt needed.
2. Move completed items to "What's done", update "What's in progress", trim "Next".
3. Keep under 150 lines — rotate oldest Done items to `PROJECT_CONTEXT_ARCHIVE.md`.
```

## Report

Summarize: resource counts per type, environments created (populated vs skeleton),
KV provider used, whether a pipeline was generated, and any unresolved references
flagged for manual review (from the CLI output / README "Manual review needed").

## Azure Pipelines — variable group vs Key Vault split

When `--cicd azure-pipelines` is used, the generated pipeline uses a shared
variable group. The **variable group is env-agnostic** — it must NOT hold any
value that differs per environment.

**Variable group** — env-agnostic values only:
- `azureServiceConnection` — Azure DevOps service connection name
- `kvName<Env>` — one entry per environment (e.g. `kvNameDev`, `kvNameProd`)

**Each env's Key Vault** — every per-env secret. At minimum:
- `auth0-domain` → `TF_VAR_auth0_domain`
- `auth0-client-id` → `TF_VAR_auth0_client_id`
- `auth0-client-secret` → `TF_VAR_auth0_client_secret`
- Any additional secrets your modules require (e.g. email provider credentials,
  custom connection keys) — add them to `SecretsFilter` and inject as `TF_VAR_*`
  in the `env:` block of the relevant plan/apply steps.

> [!IMPORTANT]
> `auth0_domain` is per-environment. **Never put it in the variable group.**
> It must be stored in each env's Key Vault as `auth0-domain` and injected via
> the `AzureKeyVault@2` task as `TF_VAR_auth0_domain: $(auth0-domain)` in the
> `env:` block of every plan/apply script step — one per stage.

## Notes

- This skill replicates to NEW tenants. Auth0-generated secrets (client secrets,
  signing secrets) are NOT set — they appear as module outputs to push into KV
  after the first apply.
- Inter-resource ID references are rewired to Terraform references automatically;
  any that could not be resolved are listed for manual review.
- Built-in Auth0 resource servers — the **Management API** (`/api/v2/`) and the
  **My Account API** (`/me/`) — and their default scope catalogues are excluded:
  every tenant auto-provisions them, so replicating them is redundant, conflicts
  with the tenant's built-ins, and would hardcode the source domain. Excluded
  resources are listed in the CLI output and the README. Custom resource servers
  are kept.
