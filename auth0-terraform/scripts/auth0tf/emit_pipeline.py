"""Emit azure-pipelines.yml: a validate stage plus plan/apply stages per env.
Approval gates for non-dev envs use Azure DevOps Environments (configured in UI).
Secrets/backend config come from a variable group — never inlined here."""
from __future__ import annotations

from pathlib import Path

HEADER = """trigger:
  branches:
    include: [main]
pr:
  branches:
    include: ['*']

variables:
  - group: auth0-terraform

pool:
  vmImage: ubuntu-latest

stages:
  - stage: validate
    jobs:
      - job: validate
        steps:
          - script: terraform fmt -check -recursive
            displayName: terraform fmt
          - script: |
              for d in envs/*/; do
                terraform -chdir="$d" init -backend=false
                terraform -chdir="$d" validate
              done
            displayName: terraform validate
"""

PLAN_TMPL = """  - stage: plan_{env}
    dependsOn: {plan_depends}
    jobs:
      - job: plan
        steps:
          - script: |
              terraform -chdir=envs/{env} init
              terraform -chdir=envs/{env} plan -out=tfplan
            displayName: plan {env}
"""

APPLY_AUTO_TMPL = """  - stage: apply_{env}
    dependsOn: plan_{env}
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - job: apply
        steps:
          - script: |
              terraform -chdir=envs/{env} init
              terraform -chdir=envs/{env} apply -auto-approve
            displayName: apply {env}
"""

APPLY_GATED_TMPL = """  - stage: apply_{env}
    dependsOn: plan_{env}
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - deployment: apply
        environment: 'auth0-{env}'
        strategy:
          runOnce:
            deploy:
              steps:
                - script: |
                    terraform -chdir=envs/{env} init
                    terraform -chdir=envs/{env} apply -auto-approve
                  displayName: apply {env}
"""


def emit_azure_pipeline(out_dir: Path, envs: list[str]) -> None:
    out_dir = Path(out_dir)
    parts = [HEADER]
    prev = "validate"
    for env in envs:
        parts.append(PLAN_TMPL.format(env=env, plan_depends=prev))
        if env == envs[0]:
            parts.append(APPLY_AUTO_TMPL.format(env=env))
        else:
            parts.append(APPLY_GATED_TMPL.format(env=env))
        prev = f"apply_{env}"
    (out_dir / "azure-pipelines.yml").write_text("\n".join(parts))
