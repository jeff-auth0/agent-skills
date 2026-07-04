"""Emit an env directory: main.tf, variables.tf, terraform.tfvars,
providers.tf, secrets.tf, backend.tf. Populated for the active tenant,
or TODO-stub skeletons for other envs."""
from __future__ import annotations

from pathlib import Path

from .emit_modules import (
    EMAIL_PROVIDER_CREDENTIALS,
    LITERAL_TYPE_MAP,
    TYPE_MAP,
    _derive_mapping,
)
from .hclgen import render_value
from .model import Tenant
from .secrets import classify_field

BACKEND_STUB = """terraform {
  # TODO: configure a remote backend before running terraform init.
  # Uncomment and fill in ONE of the blocks below.

  # --- Azure Blob Storage (azurerm) ---
  # backend "azurerm" {
  #   resource_group_name  = "my-rg"
  #   storage_account_name = "mytfstate"
  #   container_name       = "tfstate"
  #   key                  = "auth0.tfstate"
  # }

  # --- AWS S3 ---
  # backend "s3" {
  #   bucket = "my-tf-state"
  #   key    = "auth0/terraform.tfstate"
  #   region = "us-east-1"
  # }

  # --- Google Cloud Storage (gcs) ---
  # backend "gcs" {
  #   bucket = "my-tf-state"
  #   prefix = "auth0"
  # }

  # --- Terraform Cloud / HCP Terraform ---
  # backend "remote" {
  #   organization = "my-org"
  #   workspaces { name = "auth0" }
  # }
}
"""


def _present(tenant: Tenant) -> list[tuple[str, str, list]]:
    """Return (tf_type, var_name, resources) for every for_each-driven type.

    Mirrors emit_modules(): literal types are excluded (they have no tfvars/var
    wiring), curated types use their TYPE_MAP name, and any other type falls back
    to a derived name so it is wired into the env rather than silently dropped.
    """
    out = []
    for tf_type in tenant.types():
        if tf_type in LITERAL_TYPE_MAP:
            continue
        var_name = TYPE_MAP[tf_type][1] if tf_type in TYPE_MAP else _derive_mapping(tf_type)[1]
        out.append((tf_type, var_name, tenant.of_type(tf_type)))
    return out


def _providers() -> str:
    return (
        'terraform {\n'
        '  required_providers {\n'
        '    auth0 = {\n      source  = "auth0/auth0"\n      version = "= 1.49.0"\n    }\n'
        '  }\n}\n\n'
        'provider "auth0" {\n'
        '  domain        = var.auth0_domain\n'
        '  client_id     = var.auth0_client_id\n'
        '  client_secret = var.auth0_client_secret\n'
        '}\n'
    )


def _is_input_secret(tf_type: str, field: str, block_fields: set) -> bool:
    """Whether a field is a per-resource-key KV input secret (the generic
    var.<type>_secrets path). Excludes block fields and the auth0_action
    secrets/kv_secrets fields, which use their own dedicated injection path."""
    if field in block_fields:
        return False
    if tf_type == "auth0_action" and field in ("secrets", "kv_secrets", "ref_secrets"):
        return False
    return classify_field(tf_type, field) == "input"


def _actions_have_kv(present) -> bool:
    """True when any auth0_action declares kv_secrets (Key-Vault-sourced names)."""
    for tf_type, _var_name, resources in present:
        if tf_type == "auth0_action" and any(r.attrs.get("kv_secrets") for r in resources):
            return True
    return False


def _email_cred_fields(present) -> list[str]:
    """Credential field names the configured email provider sources from Key Vault
    (empty if no email provider, or its type isn't in EMAIL_PROVIDER_CREDENTIALS)."""
    for tf_type, _var_name, resources in present:
        if tf_type == "auth0_email_provider":
            for r in resources:
                fields = EMAIL_PROVIDER_CREDENTIALS.get(r.attrs.get("name"))
                if fields:
                    return fields
    return []


# for_each over every (action_key, kv_secret_name) pair declared on the actions.
_ACTION_KV_FOR_EACH = (
    "  for_each = { for pair in flatten([\n"
    "    for ak, av in var.actions : [\n"
    '      for n in try(av.kv_secrets, []) : '
    '{ key = "${ak}::${n}", action = ak, secret = n }\n'
    "    ]\n"
    "  ]) : pair.key => pair }\n"
)


def _secrets_tf(present) -> str:
    blocks = []
    for tf_type, var_name, resources in present:
        all_block_fields = set().union(*(r.block_fields for r in resources))
        secret_keys = [k for r in resources for k in r.attrs
                       if _is_input_secret(tf_type, k, all_block_fields)]
        if not secret_keys:
            continue
        blocks.append(
            f'# {var_name}_secrets — map(string) keyed by resource name.\n'
            f'# Wire this variable using ONE of:\n'
            f'#\n'
            f'# Option A — Azure Key Vault (azurerm provider):\n'
            f'#   data "azurerm_key_vault_secret" "{var_name}_secrets" {{\n'
            f'#     for_each     = var.{var_name}\n'
            f'#     name         = "auth0-${{replace(each.key, "_", "-")}}-secret"\n'
            f'#     key_vault_id = var.key_vault_id\n'
            f'#   }}\n'
            f'#   # in main.tf replace the var line with:\n'
            f'#   {var_name}_secrets = {{ for k, v in data.azurerm_key_vault_secret.{var_name}_secrets : k => v.value }}\n'
            f'#\n'
            f'# Option B — AWS Secrets Manager (aws provider):\n'
            f'#   data "aws_secretsmanager_secret_version" "{var_name}_secrets" {{\n'
            f'#     for_each  = var.{var_name}\n'
            f'#     secret_id = "auth0/${{each.key}}/secret"\n'
            f'#   }}\n'
            f'#   # in main.tf replace the var line with:\n'
            f'#   {var_name}_secrets = {{ for k, v in data.aws_secretsmanager_secret_version.{var_name}_secrets : k => v.secret_string }}\n'
            f'#\n'
            f'# Option C — GitHub Actions:\n'
            f'#   env:\n'
            f'#     TF_VAR_{var_name}_secrets: \'{{\"<resource-name>\": "${{{{ secrets.SECRET_NAME }}}}"}}\'\n'
            f'#\n'
            f'# Option D — any CI / local (env var):\n'
            f'#   export TF_VAR_{var_name}_secrets=\'{{\"<resource-name>\":\"<value>\"}}\'\n'
        )
    # Action secrets flagged for Key Vault: comment scaffold.
    if _actions_have_kv(present):
        blocks.append(
            '# actions_kv_secrets — action secrets sourced from Key Vault.\n'
            '# Keyed as "<action_name>::<SECRET_NAME>".\n'
            '# Wire using your preferred secret store (see connections_secrets above for patterns).\n'
            "# export TF_VAR_actions_kv_secrets='{\"my_action::API_KEY\":\"<value>\"}'\n"
        )
    # Email provider credentials comment scaffold.
    cred_fields = _email_cred_fields(present)
    if cred_fields:
        example_fields = ", ".join(f'"{f}":"<value>"' for f in cred_fields)
        blocks.append(
            '# email_provider_credentials — map(string) of credential fields for the email provider.\n'
            f"# export TF_VAR_email_provider_credentials='{{{example_fields}}}'\n"
            '# Or use a KV data source (see connections_secrets above for patterns).\n'
        )
    if not blocks:
        return (
            '# No external secrets detected for this tenant.\n'
            '# If you add connections with client secrets or action secrets later,\n'
            '# add injection here and wire them in main.tf.\n'
        )
    return "\n".join(blocks)


def _main_tf(present, populated: bool) -> str:
    if not populated:
        return ("# TODO: populate this environment.\n"
                "# Run the auth0-terraform skill against this tenant,\n"
                "# or copy values from a populated env and adjust.\n")
    lines = ['module "auth0" {',
             '  source      = "../../modules"',
             '  auth0_domain = var.auth0_domain']
    for tf_type, var_name, resources in present:
        lines.append(f"  {var_name} = var.{var_name}")
        all_block_fields = set().union(*(r.block_fields for r in resources))
        has_secret = any(_is_input_secret(tf_type, k, all_block_fields)
                         for r in resources for k in r.attrs)
        if has_secret:
            lines.append(f"  {var_name}_secrets = var.{var_name}_secrets")
    # Pass action KV secrets into the module, keyed "<action>::<NAME>".
    if _actions_have_kv(present):
        lines.append("  actions_kv_secrets = var.actions_kv_secrets")
    # Pass email provider credentials into the module.
    if _email_cred_fields(present):
        lines.append("  email_provider_credentials = var.email_provider_credentials")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _strip_refs(value):
    """Recursively drop dict keys whose value is a ``{"__ref__": ...}`` marker.

    Such markers (e.g. an extracted branding universal_login body) are emitted as
    hardcoded file() expressions in the module's dynamic block, so they must not
    also appear in terraform.tfvars.
    """
    if isinstance(value, list):
        return [_strip_refs(v) for v in value]
    if isinstance(value, dict):
        return {k: _strip_refs(v) for k, v in value.items()
                if not (isinstance(v, dict) and "__ref__" in v)}
    return value


def _tfvars(present, populated: bool) -> str:
    if not populated:
        return "# TODO: provide values for this environment.\n"
    out = []
    for tf_type, var_name, resources in present:
        # Compute the union of all plain fields across every instance.
        # We need a DENSE representation (every entry has every field) so that
        # Terraform can convert the raw tfvars map to map(object({...})) without
        # "attribute types must all match" errors caused by inconsistent entry shapes.
        all_block: set[str] = set()
        for r in resources:
            all_block |= r.block_fields

        all_plain: set[str] = set()
        for r in resources:
            for k, v in r.attrs.items():
                if (classify_field(tf_type, k) == "plain"
                        and not (isinstance(v, dict) and "__ref__" in v)):
                    all_plain.add(k)

        # auth0_action secrets/kv_secrets are classified "input" by name but are
        # scaffolded tfvars data (values supplied by the user), so include them.
        action_secret_fields = {"secrets", "kv_secrets"} if tf_type == "auth0_action" else set()
        all_plain |= {f for f in action_secret_fields
                      if any(f in r.attrs for r in resources)}

        # auth0_email_provider credentials are injected from Key Vault for known
        # provider types, so they must not appear (null) in tfvars.
        if tf_type == "auth0_email_provider" and any(
                EMAIL_PROVIDER_CREDENTIALS.get(r.attrs.get("name")) for r in resources):
            all_plain.discard("credentials")

        entries: dict = {}
        for r in resources:
            entry: dict = {}
            for k in all_plain:
                if k in r.attrs:
                    entry[k] = _strip_refs(r.attrs[k])
                elif k == "secrets":
                    entry[k] = {}    # dense shape: action with no secrets → {}
                elif k == "kv_secrets":
                    entry[k] = []    # dense shape: action with no kv secrets → []
                elif k in all_block:
                    entry[k] = []    # missing block field → empty list (matches optional default)
                else:
                    entry[k] = None  # missing scalar field → null
            entries[r.key] = entry
        out.append(f"{var_name} = {render_value(entries)}")
    return "\n\n".join(out) + "\n"


def _var_block(name: str, **kwargs: str) -> str:
    """Emit a multi-line `variable` block."""
    inner = "\n".join(f"  {k.ljust(9)} = {v}" for k, v in kwargs.items())
    return f'variable "{name}" {{\n{inner}\n}}\n'


def _variables_tf(present, populated: bool) -> str:
    parts = [
        _var_block("auth0_domain", type="string"),
        _var_block("auth0_client_id", type="string"),
        _var_block("auth0_client_secret", type="string", sensitive="true"),
    ]
    for tf_type, var_name, resources in present:
        parts.append(_var_block(var_name, type="any", default="{}"))
        # Add a sensitive map variable for each type that has input secrets.
        all_block_fields = set().union(*(r.block_fields for r in resources))
        has_secret = any(_is_input_secret(tf_type, k, all_block_fields)
                         for r in resources for k in r.attrs)
        if has_secret:
            parts.append(
                _var_block(f"{var_name}_secrets",
                           type="map(string)", default="{}", sensitive="true")
            )
    if _actions_have_kv(present):
        parts.append(
            _var_block("actions_kv_secrets",
                       type="map(string)", default="{}", sensitive="true")
        )
    if _email_cred_fields(present):
        parts.append(
            _var_block("email_provider_credentials",
                       type="map(string)", default="{}", sensitive="true")
        )
    return "\n".join(parts)


def emit_env(tenant: Tenant, env_dir: Path, env: str, populated: bool) -> None:
    env_dir = Path(env_dir)
    env_dir.mkdir(parents=True, exist_ok=True)
    present = _present(tenant)

    (env_dir / "providers.tf").write_text(_providers())
    (env_dir / "backend.tf").write_text(BACKEND_STUB)
    (env_dir / "main.tf").write_text(_main_tf(present, populated))
    (env_dir / "secrets.tf").write_text(_secrets_tf(present) if populated else
                                        "# TODO: wire secrets for this env.\n")
    (env_dir / "terraform.tfvars").write_text(_tfvars(present, populated))
    (env_dir / "variables.tf").write_text(_variables_tf(present, populated))
