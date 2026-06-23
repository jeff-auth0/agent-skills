"""Emit modules/<type>.tf (for_each blocks), variables.tf (typed maps),
and outputs.tf (computed secrets)."""
from __future__ import annotations

from pathlib import Path

from .hclgen import render_type, render_value, Optional as HclOptional, Raw
from .model import Tenant
from .references import (
    AUTH0_DOMAIN_LOGOUT_SENTINEL,
    MGMT_API_AUDIENCE_SENTINEL,
    REFERENCE_FIELDS,
    key_field,
    keys_field,
)
from .secrets import classify_field

# (tf_type, field) -> Terraform expression to emit instead of each.value.{field}.
# Used for fields whose values must be derived from module-level variables at apply
# time rather than stored as literals in tfvars.
DOMAIN_DERIVED_FIELDS: dict[tuple[str, str], str] = {
    ("auth0_client_grant", "audience"): (
        f'each.value.audience == "{MGMT_API_AUDIENCE_SENTINEL}"'
        ' ? "https://${var.auth0_domain}/api/v2/"'
        " : each.value.audience"
    ),
}

# Types that have domain-derived field values stored as sentinels in tfvars.
# A locals block is prepended to the .tf file and for_each uses the resolved local.
# Value: (var_name, resolved_local_name, locals_hcl_lines)
_MODULE_LOCALS: dict[str, tuple[str, str, list[str]]] = {
    "auth0_client": (
        "applications",
        "apps_resolved",
        [
            "locals {",
            "  apps_resolved = {",
            "    for k, v in var.applications : k => merge(v, {",
            "      allowed_logout_urls = [for u in coalesce(v.allowed_logout_urls, []) :",
            f'        u == "{AUTH0_DOMAIN_LOGOUT_SENTINEL}"'
            ' ? "https://${var.auth0_domain}/v2/logout" : u',
            "      ]",
            "    })",
            "  }",
            "}",
            "",
        ],
    ),
}


_SKIP_ATTRS = frozenset(("__is_block__", "__comments__"))


def _is_block_list(v) -> bool:
    """Heuristic: a non-empty list whose first item is a dict is a block-type field."""
    return isinstance(v, list) and bool(v) and isinstance(v[0], dict)


def _dynamic_block(field: str, items_sample, outer_iter: str | None = None,
                   depth: int = 1) -> list[str]:
    """Recursively emit a dynamic block.

    outer_iter: name of the enclosing iterator for nested blocks (e.g. "captcha"
    when generating the content of a dynamic "captcha" block).
    depth: indentation level (1 = top-level inside a resource block).
    """
    pad = "  " * depth
    cpd = "  " * (depth + 1)   # content padding
    spd = "  " * (depth + 2)   # sub-attr padding inside content

    if outer_iter is None:
        foreach_expr = f"coalesce(try(each.value.{field}, null), [])"
    else:
        foreach_expr = f"coalesce(try({outer_iter}.value.{field}, null), [])"

    lines = [f'{pad}dynamic "{field}" {{',
             f'{cpd}for_each = {foreach_expr}',
             f'{cpd}content {{']

    if isinstance(items_sample, list) and items_sample:
        sample = items_sample[0]
        if isinstance(sample, dict):
            sub_keys = [k for k in sample if k not in _SKIP_ATTRS]
            width = max((len(k) for k in sub_keys), default=1)
            for sk in sub_keys:
                sv = sample[sk]
                if _is_block_list(sv):
                    # nested block: recurse, outer iterator is `field`
                    lines.extend(_dynamic_block(sk, sv,
                                                outer_iter=field,
                                                depth=depth + 2))
                elif isinstance(sv, dict) and "__ref__" in sv:
                    # extracted body (e.g. branding universal_login) → file() expr
                    lines.append(f'{spd}{sk.ljust(width)} = {sv["__ref__"]}')
                else:
                    lines.append(f'{spd}{sk.ljust(width)} = {field}.value.{sk}')
    lines.append(f'{cpd}}}')
    lines.append(f'{pad}}}')
    return lines

def _nested_ref_block(field: str, items_sample, ref) -> list[str]:
    """Emit a dynamic block whose `ref.inner` field is a per-item reference to a
    target resource. After rewire(), each block's inner value holds the target's
    logical key, so it is emitted as `<target_type>.this[<iter>.value.<inner>].<attr>`
    while the other sub-attributes pass through unchanged.
    """
    sample = items_sample[0] if isinstance(items_sample, list) and items_sample else {}
    sub_keys = [k for k in sample if k not in _SKIP_ATTRS] if isinstance(sample, dict) else []
    width = max((len(k) for k in sub_keys), default=1)
    lines = [f'  dynamic "{field}" {{',
             f'    for_each = coalesce(try(each.value.{field}, null), [])',
             f'    content {{']
    for sk in sub_keys:
        if sk == ref.inner:
            lines.append(f'      {sk.ljust(width)} = '
                         f'{ref.target_type}.this[{field}.value.{sk}].{ref.target_attr}')
        else:
            lines.append(f'      {sk.ljust(width)} = {field}.value.{sk}')
    lines += ['    }', '  }']
    return lines


# tf_type -> (module filename, variable name)
# This map provides CLEAN, curated filenames/variable names for well-known types.
# It is NOT an allowlist: any parsed type not listed here (and not in
# LITERAL_TYPE_MAP) falls back to _derive_mapping() and is still emitted — see
# emit_modules(). This guarantees nothing the Auth0 CLI extracts is silently dropped.
TYPE_MAP: dict[str, tuple[str, str]] = {
    "auth0_client": ("applications.tf", "applications"),
    "auth0_resource_server": ("apis.tf", "apis"),
    "auth0_connection": ("connections.tf", "connections"),
    "auth0_role": ("roles.tf", "roles"),
    "auth0_action": ("actions.tf", "actions"),
    "auth0_tenant": ("tenant.tf", "tenant"),
    "auth0_organization": ("organizations.tf", "organizations"),
    "auth0_guardian": ("mfa.tf", "mfa"),
    "auth0_branding": ("branding.tf", "branding"),
    "auth0_attack_protection": ("security.tf", "security"),
    "auth0_flow_vault_connection": ("flow_vault_connections.tf",  "flow_vault_connections"),
    # Previously-dropped types given explicit clean names:
    "auth0_email_provider": ("email_provider.tf", "email_provider"),
    "auth0_email_template": ("email_templates.tf", "email_templates"),
    "auth0_prompt": ("prompts.tf", "prompts"),
    "auth0_prompt_custom_text": ("prompt_custom_text.tf", "prompt_custom_text"),
    "auth0_pages": ("pages.tf", "pages"),
    "auth0_branding_theme": ("branding_theme.tf", "branding_theme"),
    "auth0_custom_domain": ("custom_domains.tf", "custom_domains"),
    "auth0_log_stream": ("log_streams.tf", "log_streams"),
    "auth0_network_acl": ("network_acls.tf", "network_acls"),
    # Association / sub-resources with cross-resource references (rewired via
    # REFERENCE_FIELDS) plus ref-free singletons — curated so they validate and
    # drop off the "generically handled" review list.
    "auth0_client_credentials": ("client_credentials.tf", "client_credentials"),
    "auth0_connection_clients": ("connection_clients.tf", "connection_clients"),
    "auth0_resource_server_scopes": ("resource_server_scopes.tf", "resource_server_scopes"),
    "auth0_trigger_actions": ("trigger_actions.tf", "trigger_actions"),
    "auth0_phone_provider": ("phone_provider.tf", "phone_provider"),
    "auth0_prompt_screen_partial": ("prompt_screen_partials.tf", "prompt_screen_partials"),
}


# auth0_email_provider credential fields per provider `name`. Auth0 never returns
# credential VALUES (write-only), so for the configured provider these fields are
# injected from Key Vault (var.email_provider_credentials) rather than tfvars.
EMAIL_PROVIDER_CREDENTIALS: dict[str, list[str]] = {
    "ms365":    ["ms365_client_id", "ms365_client_secret", "ms365_tenant_id"],
    "smtp":     ["smtp_host", "smtp_port", "smtp_user", "smtp_pass"],
    "mailgun":  ["api_key", "domain", "region"],
    "ses":      ["access_key_id", "secret_access_key", "region"],
    "azure_cs": ["azure_cs_connection_string"],
    "sendgrid": ["api_key"],
    "sparkpost": ["api_key", "region"],
    "mandrill": ["api_key"],
}


def _derive_mapping(tf_type: str) -> tuple[str, str]:
    """Derive a (filename, variable_name) for a type not in TYPE_MAP.

    Strips the leading ``auth0_`` prefix and uses the remainder as both the
    variable name and the module filename stem. Ensures any future / unknown
    Auth0 resource type is still emitted rather than silently dropped.
    """
    stem = tf_type[len("auth0_"):] if tf_type.startswith("auth0_") else tf_type
    stem = stem or tf_type
    return (f"{stem}.tf", stem)

# Resource types emitted as named literal blocks rather than for_each modules.
# No variable or tfvars entry is generated — the file is self-contained and can
# be replaced by pasting output from `auth0 tf generate --resources <type>`.
LITERAL_TYPE_MAP: dict[str, str] = {
    "auth0_form":         "forms.tf",
    "auth0_flow":         "flows.tf",
    "auth0_client_grant": "client_grants.tf",
}

# File-level comment emitted at the top of each literal-resource file.
_LITERAL_FILE_COMMENTS: dict[str, str] = {
    "forms.tf": """\
# Auth0 Forms — self-contained literal resource blocks
#
# Unlike other resources (applications, roles, connections etc.) which are driven
# by terraform.tfvars, forms are defined directly here as named resource blocks.
# This means there are NO corresponding variable or tfvars entries for forms.
#
# Why: Auth0 forms are document-like configs (nodes, ending, start) that are
# exported as-is from the Auth0 CLI or dashboard. Keeping them here makes it
# trivial to update a form — just run:
#   auth0 tf generate --resources auth0_form
# and paste the output in place of the relevant block below.
""",
    "flows.tf": """\
# Auth0 Flows — self-contained literal resource blocks
#
# Like forms, flows are not driven by tfvars. Each flow is a named resource
# block defined inline. To update a flow, run:
#   auth0 tf generate --resources auth0_flow
# and paste the output in place of the relevant block below.
""",
    "client_grants.tf": """\
# Auth0 Client Grants — literal resource blocks with direct Terraform references
#
# client_id references auth0_client.this["<key>"].client_id (state-managed, no hardcoded IDs).
# Management API audience uses var.auth0_domain so it adapts to each environment.
# No corresponding variable or tfvars entry — grants are self-contained here.
""",
}


# Optional file-level comment prepended to specific for_each module files.
# Keyed by module filename (as produced by TYPE_MAP / _derive_mapping).
_MODULE_FILE_HEADERS: dict[str, str] = {
    "email_templates.tf": """\
# Auth0 Email Templates
#
# NOTE: an auth0_email_provider must be configured BEFORE templates can be
# created. These resources have no implicit dependency on email_provider.tf, so
# on a fresh tenant apply the provider first (terraform apply -target, or add a
# depends_on) to avoid an ordering failure.
""",
}


def _render_literal_field(k: str, v) -> str:
    """Render a single scalar attribute line for a literal resource block.

    A ``{"__ref__": <expr>}`` value (produced by extract_code / extract_form_bodies)
    is emitted as the raw Terraform expression (e.g. a ``file(...)`` call) rather
    than a literal object, so extracted JSON/JS bodies are referenced by file.
    """
    if isinstance(v, dict) and "__ref__" in v:
        return f"  {k} = {v['__ref__']}"
    return f"  {k} = {render_value(v)}"


def emit_literal_resources(tenant: Tenant, modules_dir: Path) -> None:
    """Emit LITERAL_TYPE_MAP resource types as named literal HCL blocks.

    Each resource becomes its own `resource "type" "key" { ... }` block with
    inline values. No for_each, no variable, no tfvars entry. The resulting
    file can be replaced wholesale by pasting Auth0 CLI output.
    """
    from .references import MGMT_API_AUDIENCE_SENTINEL
    modules_dir = Path(modules_dir)

    # Resource server identifier → Terraform key, for audience resolution in grants.
    rs_index: dict[str, str] = {
        r.attrs.get("identifier", ""): r.key
        for r in tenant.of_type("auth0_resource_server")
        if r.attrs.get("identifier")
    }

    for tf_type, filename in LITERAL_TYPE_MAP.items():
        resources = tenant.of_type(tf_type)
        if not resources:
            continue
        header = _LITERAL_FILE_COMMENTS.get(filename, "")
        blocks: list[str] = [header.rstrip()] if header else []
        for r in resources:
            lines = [f'resource "{tf_type}" "{r.key}" {{']

            if tf_type == "auth0_client_grant":
                # client_id → direct reference to auth0_client resource (state-managed)
                client_key = r.attrs.get("client_id_key")
                if client_key:
                    lines.append(f'  client_id = auth0_client.this["{client_key}"].client_id')
                # audience → Management API expression or resource server reference
                aud = r.attrs.get("audience", "")
                if aud == MGMT_API_AUDIENCE_SENTINEL:
                    lines.append('  audience  = "https://${var.auth0_domain}/api/v2/"')
                elif aud in rs_index:
                    lines.append(
                        f'  audience  = auth0_resource_server.this["{rs_index[aud]}"].identifier'
                    )
                else:
                    lines.append(f'  audience  = {render_value(aud)}')
                # remaining plain scalar fields
                skip = {"client_id", "client_id_key", "audience"}
                for k, v in r.attrs.items():
                    if k in skip or k in r.block_fields:
                        continue
                    lines.append(_render_literal_field(k, v))
            else:
                # Default: emit all scalar attributes as literals
                for k, v in r.attrs.items():
                    if k in r.block_fields:
                        continue
                    lines.append(_render_literal_field(k, v))

            # Block attributes as literal HCL blocks (no `dynamic` wrapper)
            for bf in sorted(r.block_fields):
                items = r.attrs.get(bf, [])
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    lines.append(f'  {bf} {{')
                    for sk, sv in item.items():
                        lines.append(f'    {sk} = {render_value(sv)}')
                    lines.append('  }')
            lines.append('}')
            blocks.append('\n'.join(lines))
        (modules_dir / filename).write_text('\n\n'.join(blocks) + '\n\n')


def _merged_attrs(resources) -> dict:
    """Union of attribute names across instances, with a representative value
    for type inference. Later instances win for value shape."""
    merged: dict = {}
    for r in resources:
        for k, v in r.attrs.items():
            merged[k] = v
    return merged


def _sparse_fields(resources) -> set[str]:
    """Return field names not present in every resource instance."""
    if not resources:
        return set()
    counts: dict[str, int] = {}
    for r in resources:
        for k in r.attrs:
            counts[k] = counts.get(k, 0) + 1
    total = len(resources)
    return {k for k, n in counts.items() if n < total}


def emit_modules(tenant: Tenant, modules_dir: Path) -> list[str]:
    """Emit one for_each module file per present resource type.

    Types in LITERAL_TYPE_MAP are skipped here (handled by emit_literal_resources).
    Types in TYPE_MAP get curated filenames/variable names; any other type is
    emitted via a generically-derived mapping so it is never silently dropped.

    Returns the list of tf_types that took the generic (non-curated) path, so the
    caller can surface them for review.
    """
    modules_dir = Path(modules_dir)
    modules_dir.mkdir(parents=True, exist_ok=True)

    var_blocks: list[str] = []
    output_blocks: list[str] = []
    generic_types: list[str] = []
    emit_actions_kv_secrets = False  # set when any action declares kv_secrets
    emit_email_provider_credentials = False  # set when email_provider creds → KV

    for tf_type in tenant.types():
        if tf_type in LITERAL_TYPE_MAP:
            continue  # emitted as literal blocks by emit_literal_resources
        if tf_type in TYPE_MAP:
            filename, var_name = TYPE_MAP[tf_type]
        else:
            filename, var_name = _derive_mapping(tf_type)
            generic_types.append(tf_type)
        resources = tenant.of_type(tf_type)
        merged = _merged_attrs(resources)

        # Union of block_fields across all instances of this type
        all_block_fields: set[str] = set()
        for r in resources:
            all_block_fields |= r.block_fields

        sparse = _sparse_fields(resources)

        plain_fields = [k for k in merged if classify_field(tf_type, k) == "plain"
                        and k not in all_block_fields]
        input_fields = [k for k in merged if classify_field(tf_type, k) == "input"
                        and k not in all_block_fields]
        # computed fields are neither emitted as attrs nor as outputs — they are
        # Auth0-generated and live in the Terraform state file.

        # auth0_action secrets are scaffolded synthetic fields (`secrets`,
        # `kv_secrets`); they drive a dedicated dynamic block + KV merge below,
        # so exclude them from the generic plain/input/schema handling (their
        # names would otherwise be misclassified as input secrets).
        action_secrets = tf_type == "auth0_action" and (
            "secrets" in merged or "kv_secrets" in merged or "ref_secrets" in merged)
        # per-action reference-valued secrets: { action_key: { NAME: tf_expr } }.
        # These are module-side resource references (e.g. auth0_form.x.id), kept in
        # a locals block — never in tfvars or the variable schema.
        action_ref_secrets: dict[str, dict] = {}
        if action_secrets:
            for f in ("secrets", "kv_secrets", "ref_secrets"):
                if f in plain_fields:
                    plain_fields.remove(f)
                if f in input_fields:
                    input_fields.remove(f)
            for r in resources:
                if r.attrs.get("ref_secrets"):
                    action_ref_secrets[r.key] = r.attrs["ref_secrets"]

        # auth0_email_provider: credential values are write-only (Auth0 returns
        # null), so inject the configured provider's credential fields from Key
        # Vault instead of the (null) tfvars block.
        email_cred_fields: list[str] = []
        if tf_type == "auth0_email_provider":
            email_cred_fields = EMAIL_PROVIDER_CREDENTIALS.get(merged.get("name"), [])
            if email_cred_fields:
                all_block_fields.discard("credentials")  # replace generic block

        # reference fields: rewire() replaced source-tenant ids with synthetic
        # lookup keys (kind=scalar -> `<field>_key`, kind=list -> `<field>_keys`),
        # or rewrote a nested block's inner id in place (kind=nested). Emit the
        # actual Terraform expression here.
        #   literal_skip: not emitted as a literal `f = each.value.f` attr line.
        #   schema_skip : excluded from the module's variable type object.
        # Synthetic lookup keys stay IN the schema (they are real tfvars data the
        # module needs); only the original id field and computed expressions drop.
        ref_lines: list[str] = []
        literal_skip: set[str] = set()
        schema_skip: set[str] = set()
        nested_ref_blocks: dict[str, object] = {}
        for (rtype, field), ref in REFERENCE_FIELDS.items():
            if rtype != tf_type:
                continue
            if ref.kind == "scalar":
                kf = key_field(field)
                if kf in merged:
                    ref_lines.append(
                        f"  {field} = {ref.target_type}.this[each.value.{kf}].{ref.target_attr}"
                    )
                    literal_skip.add(kf)
            elif ref.kind == "list":
                kfs = keys_field(field)
                if kfs in merged:
                    ref_lines.append(
                        f"  {field} = [for k in each.value.{kfs} : "
                        f"{ref.target_type}.this[k].{ref.target_attr}]"
                    )
                    literal_skip.add(kfs)
            elif ref.kind == "nested":
                if field in all_block_fields:
                    nested_ref_blocks[field] = ref

        # __ref__ fields: values replaced by extract_code with a hard-coded
        # for_each-compatible expression (e.g. file(".../${each.value.name}.js")).
        # Emit the expression directly; exclude from the variable schema and tfvars.
        for f in list(plain_fields):
            v = merged.get(f)
            if isinstance(v, dict) and "__ref__" in v:
                ref_lines.append(f"  {f} = {v['__ref__']}")
                literal_skip.add(f)
                schema_skip.add(f)

        # domain-derived fields: emit a computed expression instead of each.value.{f}
        for (rtype, field), expr in DOMAIN_DERIVED_FIELDS.items():
            if rtype == tf_type and field in merged:
                ref_lines.append(f"  {field} = {expr}")
                literal_skip.add(field)
                schema_skip.add(field)

        literal_plain = [f for f in plain_fields if f not in literal_skip]

        # resource block
        _ml = _MODULE_LOCALS.get(tf_type)
        foreach_src = f"local.{_ml[1]}" if _ml else f"var.{var_name}"
        lines = [f'resource "{tf_type}" "this" {{',
                 f"  for_each = {foreach_src}"]
        width = max([len(f) for f in literal_plain + input_fields] or [1])
        for f in literal_plain:
            lines.append(f"  {f.ljust(width)} = each.value.{f}")
        for f in input_fields:
            lines.append(f"  {f.ljust(width)} = var.{var_name}_secrets[each.key]")
        lines.extend(ref_lines)
        # dynamic blocks for block-type fields (nested reference blocks emit a
        # per-item lookup for their inner id field; all others pass through).
        for bf in sorted(all_block_fields):
            if bf not in merged:
                continue
            if bf in nested_ref_blocks:
                lines.extend(_nested_ref_block(bf, merged[bf], nested_ref_blocks[bf]))
            else:
                lines.extend(_dynamic_block(bf, merged[bf]))
        # auth0_action secrets: merge hardcoded tfvars values with Key-Vault-sourced
        # ones (var.actions_kv_secrets, keyed "<action>::<name>"), then emit a block
        # per resulting secret. Values not extractable from Auth0 — supplied by IaC.
        if action_secrets:
            merge_lines = [
                '    for_each = merge(',
                '      try(each.value.secrets, {}),',
                '      { for n in try(each.value.kv_secrets, []) : '
                'n => var.actions_kv_secrets["${each.key}::${n}"] },',
            ]
            if action_ref_secrets:
                # resource-reference-valued secrets (e.g. a form id generated in
                # this tenant), looked up per-action from the locals block below.
                merge_lines.append(
                    '      lookup(local.action_secret_refs, each.key, {}),')
            merge_lines.append('    )')
            lines += ['  dynamic "secrets" {', *merge_lines,
                      '    content {',
                      '      name  = secrets.key',
                      '      value = secrets.value',
                      '    }',
                      '  }']
        # auth0_email_provider credentials sourced from Key Vault
        if email_cred_fields:
            emit_email_provider_credentials = True
            w = max(len(f) for f in email_cred_fields)
            lines.append("  credentials {")
            for f in email_cred_fields:
                expr = f'var.email_provider_credentials["{f}"]'
                if f.endswith("_port"):
                    expr = f'tonumber({expr})'  # smtp_port is a number
                lines.append(f"    {f.ljust(w)} = {expr}")
            lines.append("  }")
        lines.append("}")
        # Reference-valued action secrets live in a locals block (resource refs
        # can't sit in tfvars); the secrets merge looks them up per-action key.
        prelude = ""
        if _ml:
            prelude += "\n".join(_ml[2]) + "\n"
        if action_ref_secrets:
            ref_lines2 = [
                "locals {",
                "  # Action-secret values that reference a resource generated in this",
                "  # tenant (ids differ per tenant). Edit to add or adjust references.",
                "  action_secret_refs = {",
            ]
            for akey in sorted(action_ref_secrets):
                ref_lines2.append(f"    {akey} = {{")
                pairs = action_ref_secrets[akey]
                w = max(len(n) for n in pairs)
                for n in sorted(pairs):
                    ref_lines2.append(f"      {n.ljust(w)} = {pairs[n]}")
                ref_lines2.append("    }")
            ref_lines2 += ["  }", "}", ""]
            prelude = "\n".join(ref_lines2) + "\n"
        header = _MODULE_FILE_HEADERS.get(filename, "")
        body = "\n".join(lines) + "\n"
        (modules_dir / filename).write_text(
            (header + "\n" if header else "") + prelude + body)

        # variable block: typed map over scalar plain fields; block fields use list(any)
        # Sparse plain fields → optional(inferred_type)
        # All block fields   → optional(list(any), []) — absent block = empty list
        type_obj = {}
        for f in plain_fields:
            if f in schema_skip:
                continue
            val = merged[f]
            type_obj[f] = HclOptional(val) if f in sparse else val
        for bf in sorted(all_block_fields):
            if bf in merged:
                type_obj[bf] = HclOptional(None, default=[])  # optional(any, []) — avoids inter-entry type unification failure
        if action_secrets:
            # explicit types — inference would produce a per-action object() that
            # won't unify across the map. kv_secrets is consumed by the merge above.
            type_obj["secrets"] = HclOptional(Raw("map(string)"), default={})
            type_obj["kv_secrets"] = HclOptional(Raw("list(string)"), default=[])
            # the secrets block always references var.actions_kv_secrets, so the
            # variable must be declared even if no action uses KV yet.
            emit_actions_kv_secrets = True
        var_blocks.append(
            f'variable "{var_name}" {{\n'
            f"  type = map({render_type(type_obj)})\n"
            f"  default = {{}}\n}}\n"
        )
        if input_fields:
            var_blocks.append(
                f'variable "{var_name}_secrets" {{\n'
                f"  type      = map(string)\n"
                f"  sensitive = true\n"
                f"  default   = {{}}\n}}\n"
            )

        # NOTE: computed fields (client_id, client_secret, signing_secret, …) are
        # intentionally NOT emitted as outputs. They are Auth0-generated and live
        # in the Terraform state file; they are neither injected nor pushed to KV.

    # Key-Vault-sourced action secrets, keyed "<action_key>::<SECRET_NAME>",
    # supplied by the env layer (see emit_env). Merged into each action's secrets.
    if emit_actions_kv_secrets:
        var_blocks.append(
            'variable "actions_kv_secrets" {\n'
            "  type      = map(string)\n"
            "  sensitive = true\n"
            "  default   = {}\n}\n"
        )

    # Key-Vault-sourced email provider credentials, keyed by credential field name.
    if emit_email_provider_credentials:
        var_blocks.append(
            'variable "email_provider_credentials" {\n'
            "  type      = map(string)\n"
            "  sensitive = true\n"
            "  default   = {}\n}\n"
        )

    # auth0_domain is required by domain-derived field expressions (e.g. /api/v2/ audience)
    var_blocks.insert(0, 'variable "auth0_domain" {\n  type = string\n}\n')
    (modules_dir / "variables.tf").write_text("\n".join(var_blocks))
    (modules_dir / "outputs.tf").write_text("\n".join(output_blocks))
    (modules_dir / "versions.tf").write_text(
        'terraform {\n'
        '  required_providers {\n'
        '    auth0 = {\n'
        '      source  = "auth0/auth0"\n'
        '      version = "= 1.49.0"\n'
        '    }\n'
        '  }\n'
        '}\n'
    )
    return generic_types
