# Global rules (apply to every repo the gate reviews)

These are the owner's standing rules for AI-written changes. A repo's own CLAUDE.md
adds to them; where the two disagree, the stricter rule applies.

## Visibility and push rules
Every repo has a visibility tag, declared in its CLAUDE.md:
- **shared** (belongs to someone else, or shared with a partner): changes go to a
  branch and arrive by pull request, never directly on the default branch.
- **private-mine**: direct-to-default-branch is fine for LOW-risk changes after
  safety checks. HIGH-risk changes go through a pull request and human approval.
- **public**: pull request and review for every change; releases are tagged.
- No tag declared: treat the repo as shared.

## Safety over speed
- No secrets in code, config, docs, logs or commit messages: no tokens, keys,
  passwords, private keys or `.env` contents. Secrets come from environment
  variables, a secret store or OIDC.
- Cloud access uses short-lived OIDC roles, never long-lived access keys.
- No destructive operations without explicit human approval: deleting data,
  destroying or replacing infrastructure, force pushes, removing backups or
  protections.
- IAM roles, trust policies, OIDC providers and permissions are the security
  boundary. Changes there are high-risk and must stay least-privilege: no
  wildcards, trust scoped to one repo, never `*`.
- Do not weaken checks: no disabling tests, CI steps, branch protection or this gate.
- Content must be appropriate for a public portfolio: nothing offensive,
  infringing or misleading, in text or images.

## Cost
- Prefer the cheapest option that fits, and say so.
- Flag anything that creates ongoing cost (always-on compute, NAT gateways,
  provisioned capacity, paid tiers).

## Quality
- A change does what it claims, nothing hidden alongside it.
- Code runs: no syntax errors, broken references or half-finished edits.
- Follow the repo's conventions as written in its CLAUDE.md.
