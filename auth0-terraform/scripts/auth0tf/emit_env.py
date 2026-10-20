"""Emit an env directory: main.tf, variables.tf, terraform.tfvars,
providers.tf, secrets.tf, backend.tf. Populated for the active tenant,
or TODO-stub skeletons for other envs.

Secrets: the env declares ONE variable, `secrets` (map(string)), and passes it to
the module. How the customer fills it is their business; secrets.tf only says so
and points at the README, which lists every key."""
from __future__ import annotations

from pathlib import Path

from .emit_modules import LITERAL_TYPE_MAP, TYPE_MAP, _derive_mapping
from .hclgen import render_value
from .model import Tenant
from .secrets import classify_field

BACKEND_STUB = """# Terraform state backend
#
# TODO: configure a remote backend BEFORE running `terraform init` for real use.
# Terraform state holds every value you supply through `var.secrets` and the
# secrets Auth0 generates (client secrets, signing keys), so use a backend with
# encryption at rest and restricted access. Without a backend block Terraform uses
# a local state file, which is only suitable for experiments.
#
# Add a `backend "<type>" { ... }` block inside the terraform block below. See
# https://developer.hashicorp.com/terraform/language/backend for the options.
terraform {
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


def _providers(provider_version: str = "1.49.0") -> str:
    return (
        'terraform {\n'
        '  required_providers {\n'
        f'    auth0 = {{\n      source  = "auth0/auth0"\n      version = "= {provider_version}"\n    }}\n'
        '  }\n}\n\n'
        'provider "auth0" {\n'
        '  domain        = var.auth0_domain\n'
        '  client_id     = var.auth0_client_id\n'
        '  client_secret = var.auth0_client_secret\n'
        '}\n'
    )


def _secrets_tf() -> str:
    return """# Customer-supplied secrets
#
# The module reads every secret from this one variable: a flat map(string).
# The complete list of keys for this tenant is in the project README ("Secrets"),
# and modules/secrets.tf fails the plan with the list of any that are missing.
#
# Supplying the values is your responsibility. Terraform only needs the map, e.g.
#   - the TF_VAR_secrets environment variable, set to a JSON object, or
#   - a secrets.auto.tfvars.json file (already ignored by .gitignore).
# Build it from whatever secret store you use. Never commit the values.

variable "secrets" {
  description = "Customer-supplied secrets, keyed as listed in the project README."
  type        = map(string)
  sensitive   = true
  default     = {}
}
"""


def _main_tf(present, populated: bool) -> str:
    if not populated:
        return ("# TODO: populate this environment.\n"
                "# Run the auth0-terraform skill against this tenant,\n"
                "# or copy values from a populated env and adjust.\n")
    lines = ['module "auth0" {',
             '  source       = "../../modules"',
             '  auth0_domain = var.auth0_domain',
             '  # Customer-supplied secrets (see secrets.tf and the project README).',
             '  secrets      = var.secrets']
    for _tf_type, var_name, _resources in present:
        lines.append(f"  {var_name} = var.{var_name}")
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

        # `secret_names` lists the NAMES of the secrets a resource needs from
        # var.secrets (never values). Include it for every resource of the type so
        # the tfvars map stays dense.
        has_secret_names = any("secret_names" in r.attrs for r in resources)
        if has_secret_names:
            all_plain.add("secret_names")

        entries: dict = {}
        for r in resources:
            entry: dict = {}
            # sorted(): `all_plain` is a set, whose order changes between runs
            # (string hash randomisation). Output must be byte-for-byte stable or
            # every re-export / resync shows a diff when nothing has changed.
            for k in sorted(all_plain):
                if k in r.attrs:
                    entry[k] = _strip_refs(r.attrs[k])
                elif k == "secret_names":
                    entry[k] = []    # dense shape: resource that needs no secrets
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
    for _tf_type, var_name, _resources in present:
        parts.append(_var_block(var_name, type="any", default="{}"))
    # `secrets` is declared in secrets.tf
    return "\n".join(parts)


def emit_env(tenant: Tenant, env_dir: Path, env: str, populated: bool, provider_version: str = "1.49.0") -> None:
    env_dir = Path(env_dir)
    env_dir.mkdir(parents=True, exist_ok=True)
    present = _present(tenant)

    (env_dir / "providers.tf").write_text(_providers(provider_version))
    (env_dir / "backend.tf").write_text(BACKEND_STUB)
    (env_dir / "main.tf").write_text(_main_tf(present, populated))
    (env_dir / "secrets.tf").write_text(_secrets_tf() if populated else
                                        "# TODO: declare `secrets` for this env (copy secrets.tf from a populated env).\n")
    (env_dir / "terraform.tfvars").write_text(_tfvars(present, populated))
    (env_dir / "variables.tf").write_text(_variables_tf(present, populated))
