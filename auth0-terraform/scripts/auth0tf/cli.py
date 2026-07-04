"""Orchestrate the full transformation. Used by SKILL.md and as a CLI."""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from .emit_env import emit_env
from .emit_modules import emit_literal_resources, emit_modules
from .emit_pipeline import emit_azure_pipeline
from .emit_readme import emit_readme
from .extract import (
    extract_branding_templates,
    extract_code,
    extract_email_bodies,
    extract_form_bodies,
    scaffold_action_secrets,
)
from .parse import parse_dir
from .references import (
    exclude_builtin_apis,
    rekey_client_grants,
    rewire,
    rewire_domain_audiences,
    rewire_domain_logout_urls,
)


def run(input_path: str, out_dir: str, env: str,
        other_envs: list[str], cicd: str) -> dict:
    out = Path(out_dir)
    modules = out / "modules"
    modules.mkdir(parents=True, exist_ok=True)

    tenant = parse_dir(input_path)

    scaffold_action_secrets(tenant)        # before extract_code: scan code for secrets.*
    extract_code(tenant, modules)          # before emit: replaces inline code
    extract_form_bodies(tenant, modules)   # before emit: form/flow JSON bodies → files
    extract_email_bodies(tenant, modules)  # before emit: email template bodies → files
    extract_branding_templates(tenant, modules)  # before emit: universal login body → file
    rewire_domain_audiences(tenant)        # before emit: sentinel for /api/v2/ audiences
    excluded = exclude_builtin_apis(tenant)  # before rewire: drop built-in Auth0 APIs (Mgmt + My Account) + scopes
    # counts reflect what is actually emitted (after exclusion of auto-provisioned resources)
    counts = dict(Counter(r.tf_type for r in tenant.resources))
    unresolved = sorted(rewire(tenant))    # before emit: fix cross-resource ID refs
    rewire_domain_logout_urls(tenant)      # after rewire: sentinel for client logout URLs
    rekey_client_grants(tenant)            # after rewire: stable human-readable grant keys

    generic_types = emit_modules(tenant, modules)
    emit_literal_resources(tenant, modules)
    emit_env(tenant, out / "envs" / env, env=env, populated=True)
    for other in other_envs:
        emit_env(tenant, out / "envs" / other, env=other, populated=False)

    all_envs = [env] + list(other_envs)
    if cicd == "azure-pipelines":
        emit_azure_pipeline(out, envs=all_envs)

    emit_readme(out, counts=counts, envs=all_envs, unresolved=unresolved,
                generic_types=generic_types, excluded=excluded)
    return {"counts": counts, "unresolved": unresolved, "envs": all_envs,
            "generic_types": generic_types, "excluded": excluded}


def emit_pipeline_cmd(project_dir: str, envs: list[str], cicd: str) -> None:
    out = Path(project_dir)
    if cicd == "azure-pipelines":
        emit_azure_pipeline(out, envs=envs)
    elif cicd in ("github-actions", "gitlab-ci"):
        print(f"Pipeline generation for {cicd} is not yet supported — scaffold manually.")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="Restructure auth0 tf generate output.")
    sub = p.add_subparsers(dest="command")

    t = sub.add_parser("transform", help="Parse raw tf output into structured project")
    t.add_argument("--input", required=True)
    t.add_argument("--out", required=True)
    t.add_argument("--env", required=True)
    t.add_argument("--other-envs", default="")

    pl = sub.add_parser("pipeline", help="Generate CI/CD pipeline file")
    pl.add_argument("--project-dir", required=True)
    pl.add_argument("--envs", required=True, help="comma-separated env names")
    pl.add_argument("--cicd", choices=["azure-pipelines", "github-actions", "gitlab-ci", "none"],
                    required=True)

    a = p.parse_args(argv)

    if a.command == "transform":
        others = [e.strip() for e in a.other_envs.split(",") if e.strip()]
        result = run(a.input, a.out, a.env, others, cicd="none")
        print(f"Done. Resources: {result['counts']}. Unresolved refs: {result['unresolved']}.")
        if result.get("excluded"):
            print("Excluded (auto-provisioned by Auth0, not replicated): "
                  + "; ".join(result["excluded"]))
        if result.get("generic_types"):
            print("Auto-handled (generic emission, review naming/structure): "
                  + ", ".join(sorted(result["generic_types"])))

    elif a.command == "pipeline":
        envs = [e.strip() for e in a.envs.split(",") if e.strip()]
        emit_pipeline_cmd(a.project_dir, envs, a.cicd)
        if a.cicd != "none":
            print(f"Pipeline generated: {a.cicd}")

    else:
        p.print_help()


if __name__ == "__main__":
    main()
