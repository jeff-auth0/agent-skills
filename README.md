# agent-skills

Reusable Claude Code skills for Auth0, Terraform, and DevOps workflows — install with `npx skills add`.

## Available Skills

| Skill | Description |
|---|---|
| [auth0-terraform](./auth0-terraform) | Reverse-engineer an active Auth0 tenant into a multi-environment Terraform project |

## Install all skills

```bash
npx skills add jeff-auth0/agent-skills -g
```

## Install a single skill

```bash
npx skills add jeff-auth0/agent-skills@auth0-terraform -g
```

## Usage

Once installed, invoke a skill by describing the task in Claude Code:

```
generate terraform for my auth0 tenant
```

Claude will find and follow the relevant skill automatically.

## Adding a skill

Each skill lives in its own subdirectory with a `SKILL.md` and a `README.md`:

```
agent-skills/
└── your-skill/
    ├── SKILL.md      # agent instructions
    └── README.md     # human-facing docs
```

See the [skills.sh specification](https://agentskills.io/specification) for the `SKILL.md` format.
