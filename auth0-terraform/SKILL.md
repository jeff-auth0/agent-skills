---
name: auth0-terraform
description: Use when you want to reverse-engineer an active Auth0 tenant into a structured, multi-environment Terraform project for replicating that tenant into new empty tenants. Runs `auth0 tf generate`, then restructures the flat output into a `modules/` directory (one `for_each` block per resource type with typed map variables), per-environment `envs/` directories, extracted action/DB-script files, a single `secrets` variable with a generated list of every key the customer must supply, and a customer-facing README. Vendor neutral - no CI/CD pipeline and no vault wiring is generated; the customer owns both. Trigger on prompts like "generate terraform for my auth0 tenant", "reverse engineer auth0 to terraform", "structure my auth0 terraform".
---

# Auth0 → Terraform Project Generator

Generates a clean, multi-environment Terraform project from an active Auth0 tenant, designed to **replicate** the tenant into new, empty tenants.

## Prerequisites check

1. Run `auth0 --version`. If missing, tell the user to install the Auth0 CLI and stop.
2. Run `python3 -c "import hcl2"` from the skill dir. If it fails, run
   `python3 -m pip install -e .` in the skill directory.
3. Run `terraform version`. **Terraform 1.11 or later is required** (the Auth0
   provider uses write-only attributes). The `terraform` binary bundled by the
   Auth0 CLI is older and cannot validate the generated project; if the system
   one is too old, tell the user to upgrade it and stop.
4. Run `auth0 tenants list`. Show the active tenant. **Ask the user to confirm
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
export AUTH0_DOMAIN=<tenant-domain>          # e.g. my-tenant.us.auth0.com
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
  generated project (each env supplies its own provider credentials).

#### How to obtain the credentials from the user (do this BEFORE the three questions)

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

## Mode selection

After the tenant is confirmed, ask **one question**:

> **New project or resync?**
> - **New project**: generate a fresh Terraform project from this tenant (continue below).
> - **Resync**: pull changes made in the dashboard since the last export into an existing generated project (jump to "Resync an existing project").

Do not continue without a clear answer.

## Ask these three questions (one message, in order)

1. Environment name for this active tenant (e.g. `dev`, `staging`, `prod`).
2. Other environment names to scaffold as empty skeletons (comma-separated, may be blank).
3. **Output path** — full absolute path where the generated Terraform project should be
   written (e.g. `~/projects/rclb-terraform`). No default — always ask. Use this path
   as `--out` in the transformer step.

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
2. Run the transformer (from the skill directory), passing the user's output path
   from question 3 as `--out`. Expand `~` before passing — the transformer runs
   from the skill dir, so relative paths resolve there, not the user's cwd:
   ```bash
   OUT=$(eval echo "<user-supplied-path>")   # expands ~ correctly
   python3 -m scripts.auth0tf.cli transform \
     --input /tmp/auth0tf-raw \
     --out "$OUT" \
     --env <env> \
     --other-envs "<comma,separated>"
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

   # Local variable overrides. secrets.auto.tfvars.json is where a customer may put
   # the `secrets` map (see README); it must never be committed.
   *.auto.tfvars
   *.auto.tfvars.json

   # .terraform.lock.hcl is intentionally committed for provider version reproducibility

   # Local credentials / export helpers
   .env
   .env.*
   auth0tf.env
   ```
   Note: `terraform.tfvars` is **not** ignored — it contains non-secret config and
   is intentionally committed. `.terraform.lock.hcl` is **not** ignored — kept for
   provider version reproducibility.
4. Run `terraform validate` with the **system** `terraform` (1.11 or later; checked in
   Prerequisites):
   ```bash
   terraform -chdir="$OUT/envs/<env>" init -backend=false
   terraform -chdir="$OUT/envs/<env>" validate
   ```
   Do not use the binary the Auth0 CLI leaves in `/tmp/auth0tf-raw`: it is older
   (1.5) and rejects the write-only attributes with "Write-only Attribute Not
   Allowed". Report any validate errors.
5. Check that the secrets contract works. Supply the keys listed in the generated
   README with dummy values and confirm `plan` gets past variable evaluation:
   ```bash
   cd "$OUT/envs/<env>"
   export TF_VAR_auth0_domain=x.au.auth0.com TF_VAR_auth0_client_id=x TF_VAR_auth0_client_secret=x
   terraform plan -refresh=false          # no secrets: expect ONE "Missing required secrets" list
   ```
   With no `secrets` supplied the plan must stop with a single error that lists
   every missing key. That list must match the README table. Do not put real values
   in this check.

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
Terraform project generated from <tenant-domain>. Awaiting secrets, a state backend and the first plan.

## What's done
- Generated Terraform project from <tenant-domain> (<N> resources across <M> resource types)
- Environments scaffolded: <list>
- Secrets: <N> keys the customer must supply through `var.secrets` (listed in README.md)
- CI/CD and secret binding: left to the customer

## What's in progress
- Nothing — project generated; the customer wires secrets and the state backend

## Decisions made
- Secrets come from one `secrets` variable (flat dotted keys); no values are stored in the repo
- The tool generates no vault or CI/CD wiring; that is the customer's responsibility
- terraform.tfvars committed (non-secret config only)
- .terraform.lock.hcl committed (provider version reproducibility)

## Next / backlog (ordered)
1. Provide the `secrets` map (keys listed in README.md, section Secrets)
2. Configure the state backend in `envs/<env>/backend.tf`
3. Run `terraform plan` for the first env — verify expected adds (state is empty on first run)
4. Review plan output, then run apply
5. Populate and repeat for the remaining environments

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

## Resync an existing project

Use this when someone changed the tenant in the dashboard (ClickOps) and the existing
project must catch up **without losing the customer's own edits**.

### How it works
Every managed file is merged three ways:

| Version | Meaning |
|---|---|
| baseline | what the generator produced last time (`.auth0tf/baseline/`, stored in the project) |
| tenant | what the generator produces now |
| project | what is on disk, possibly edited by the customer |

If the tenant did not change a file, it is left alone. If only the tenant changed it, the
tenant version is taken. If both changed it, `git merge-file` merges the hunks and writes
conflict markers where they overlap. Resync touches only `modules/`, `envs/<env>/`,
`README.md` and `.auth0tf/`. Other environments, `backend.tf` edits, `.gitignore`,
`PROJECT_CONTEXT.md` and files the customer added are never written.

It works on a new branch (`auth0/resync`), commits there, and **never pushes**.

### Steps
1. **Show the tenant prominently** and confirm: `Syncing tenant: <tenant-domain>`.
2. **Ask for the project path** (default: the current directory). It must contain
   `modules/`, `envs/` and `.auth0tf/`. A project without `.auth0tf/` was generated
   before resync existed: it cannot be resynced, so re-export it with the new-project flow.
3. **Ask which env maps to this tenant** (list the directories under `envs/`).
4. **Collect credentials** the same way as for a new project (env file recommended).
5. **Pull fresh tenant state** into `/tmp/auth0tf-raw` (see Generate, step 1, including the
   fallback when `auth0_generated.tf` is missing).
6. **Dry run first**, from the skill directory, and show the report:
   ```bash
   python3 -m scripts.auth0tf.cli resync --input /tmp/auth0tf-raw \
     --project "$PROJECT" --env <env> --dry-run
   ```
7. **Run it for real** once the user agrees (drop `--dry-run`). The project must have no
   uncommitted changes in managed files; otherwise resync stops and changes nothing.
8. **Report** to the user, from the command output:
   - resources `+ added`, `~ changed`, `- removed`;
   - **removed resources: warn clearly.** Applying a project that no longer has them will
     destroy them in any tenant that does. A rename appears as a removal plus an addition;
   - **new secret keys** the customer must add to `secrets` (otherwise `plan` fails);
   - the branch name and commit, and `git diff auth0/resync~1 auth0/resync` to review;
   - any **conflicts**: files with markers fail `terraform validate` on purpose. List them
     and the commits that touched them; the customer resolves them by hand.
9. **Update `PROJECT_CONTEXT.md`** if it exists: append to "What's done" (date, branch), and
   put unresolved conflicts or new secret keys under "What's in progress".

### Exit codes and flags
`0` ok or nothing to do, `1` finished with conflicts, `2` refused (no baseline, wrong env,
not a git repo, uncommitted managed files). Nothing is changed on a refusal.
`--no-git` writes in place without a branch; `--branch NAME` picks the branch name.

### Limits to tell the user
- A resource renamed in the dashboard looks like a removal plus an addition.
- Secret **values** are never seen; resync can only add or remove key names.
- `terraform.tfvars` is one large file, so a customer edit right next to a tenant change can
  conflict. Output is sorted and one attribute per line to keep that rare.

## Report

Summarize: resource counts per type, environments created (populated vs skeleton),
the number of secret keys the customer must supply, and any unresolved references
or review items. Point the user at `README.md` in the output directory: its
**Secrets** section is the authoritative list of keys, and its **Values that differ
per environment** section lists what to change for each target tenant.

## Secrets

The generated project has no vault, CI or cloud-provider code. All customer-supplied
values go through **one variable**:

```hcl
variable "secrets" { type = map(string), sensitive = true }
```

Keys are flat and dotted: `<variable>.<resource key>.<name>`, with the resource key
omitted for singletons (`email_provider.api_key`,
`actions.my_action.API_KEY`, `connections.my_db.configuration.base_uri`).

- `modules/secrets.tf` declares the variable and fails `plan` with one message that
  lists every missing key.
- `README.md` lists every required key, generated from the same data, so the two
  cannot disagree.
- How the customer fills the map (an env var `TF_VAR_secrets`, a gitignored
  `secrets.auto.tfvars.json`, built from any vault or CI) is **their responsibility**.
  Do not generate or suggest vendor-specific wiring.
- Which values count as secrets is decided in one place, `secret_binding.py`, from
  an explicit table (`secrets.py`) based on the provider schema, not on field names.
  Sensitive settings the export cannot reveal (addons, CAPTCHA keys, push MFA ...) are
  listed in the README for the customer to add by hand.

Auth0-generated secrets (client secrets, signing keys) are created on apply and live
in Terraform state; the customer never supplies them.

## Notes

- This skill replicates to NEW tenants.
- No CI/CD pipeline is generated. Pipelines, secret stores and state backends belong
  to the customer; the README says what is needed.
- Inter-resource ID references are rewired to Terraform references automatically;
  any that could not be resolved are listed for manual review.
- Built-in Auth0 resource servers — the **Management API** (`/api/v2/`) and the
  **My Account API** (`/me/`) — and their default scope catalogues are excluded:
  every tenant auto-provisions them, so replicating them is redundant, conflicts
  with the tenant's built-ins, and would hardcode the source domain. Excluded
  resources are listed in the CLI output and the README. Custom resource servers
  are kept.
- `.auth0tf/` (baseline and state used by resync) is part of the project: commit it.
- The `connections` variable is declared `type = any` because connections with
  differently shaped nested blocks cannot share one object type (see
  `LOOSELY_TYPED` in `emit_modules.py`).
