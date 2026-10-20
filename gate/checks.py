"""The checks that code decides, not the model.

- Secret scan: runs on every added line BEFORE any model call. A hit fails the
  gate on the spot and the model is never called, so a leaked secret is never
  sent to any provider.
- Risk signals: path and keyword rules that force risk_tier "high". The model
  can raise the tier, never lower it below these.
- Branch rule: a lookup on visibility + target branch + how the change arrives.
  It is a fact, so a model is not asked to judge it.
- Repo declarations: the machine-readable visibility / risk-floor lines in a
  repo's CLAUDE.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .diffutil import FileDiff

# --- Secrets -------------------------------------------------------------------

SECRET_PATTERNS = [
    ("aws-access-key-id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws-secret-access-key", re.compile(
        r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}\b")),
    ("github-token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("openai-key", re.compile(r"\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("xai-key", re.compile(r"\bxai-[A-Za-z0-9]{40,}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("discord-webhook", re.compile(r"https://(ptb\.|canary\.)?discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{30,}")),
    ("private-key-block", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("password-or-token-assignment", re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|client[_-]?secret)\b\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]")),
]

# Values that look like an assignment but are obviously placeholders.
_PLACEHOLDER = re.compile(
    r"(?i)(your[-_]|example|placeholder|changeme|dummy|redacted|xxxx|\.\.\.|<|\$\{|\$\{\{|%\(|os\.environ|process\.env)")


@dataclass
class SecretFinding:
    path: str
    rule: str
    diff_line: int
    preview: str      # redacted, safe to print and to publish in a PR comment


def _redact(value: str) -> str:
    # No characters of the value at all: previews can end up in a public PR comment.
    return f"[redacted, {len(value)} chars]"


def scan_secrets(files: list[FileDiff]) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for f in files:
        name = f.path.rsplit("/", 1)[-1]
        if f.status != "deleted" and (name == ".env" or (name.endswith(".env") and name != ".env.example")
                                      or name.startswith(".env.") and name not in (".env.example", ".env.sample")):
            findings.append(SecretFinding(f.path, "env-file-committed", 0, "a .env file is part of the change"))
        for line_no, text in f.added:
            for rule, pat in SECRET_PATTERNS:
                for m in pat.finditer(text):
                    value = m.group(2) if rule == "password-or-token-assignment" else m.group(0)
                    if rule == "password-or-token-assignment" and _PLACEHOLDER.search(value):
                        continue
                    findings.append(SecretFinding(f.path, rule, line_no, _redact(value)))
    return findings


def redact_secrets(text: str) -> str:
    """Replace anything that matches a secret pattern. Defense in depth only:
    the engine refuses to call a model at all when scan_secrets finds something.

    Uses the same placeholder rule as scan_secrets: redacting `PASSWORD="changeme"`
    would show the reviewer a [REDACTED] marker and make it suspect a real secret."""
    def replacer(rule):
        def repl(m):
            if rule == "password-or-token-assignment" and _PLACEHOLDER.search(m.group(2)):
                return m.group(0)
            return f"[REDACTED:{rule}]"
        return repl

    for rule, pat in SECRET_PATTERNS:
        text = pat.sub(replacer(rule), text)
    return text


# --- Risk signals ----------------------------------------------------------------

_RISKY_PATHS = [
    (re.compile(r"(^|/)\.github/workflows/"), "CI/CD workflow change"),
    (re.compile(r"\.tf$|\.tfvars$|\.hcl$"), "infrastructure-as-code change"),
    (re.compile(r"(^|/)(CLAUDE\.md|\.claude/)"), "agent governance rules change"),
    (re.compile(r"(^|/)(Dockerfile|docker-compose[^/]*\.ya?ml)$"), "container build change"),
    (re.compile(r"(^|/)(wrangler\.toml|serverless\.ya?ml|template\.ya?ml|cdk\.json)$"), "deployment config change"),
    (re.compile(r"(^|/)(CODEOWNERS|\.gitignore)$"), "repo protection file change"),
]

_RISKY_TEXT = [
    (re.compile(r"aws_iam_|\biam:|AssumeRole|assume_role_policy|\"Principal\"|principals\s*\{"), "IAM / trust policy"),
    (re.compile(r"aws_iam_openid_connect_provider|token\.actions\.githubusercontent\.com"), "OIDC trust"),
    (re.compile(r"\"Action\"\s*:\s*\"\*\"|actions\s*=\s*\[\s*\"\*\"\s*\]|\b[a-z0-9-]+:\*\""), "wildcard permissions"),
    (re.compile(r"terraform\s+destroy|force_destroy\s*=\s*true|prevent_destroy\s*=\s*false|-auto-approve"), "destructive infrastructure operation"),
    (re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\bDROP\s+(TABLE|DATABASE)\b|\bTRUNCATE\s+TABLE\b", re.I), "destructive command"),
    (re.compile(r"git\s+push\s+(.*\s)?(--force|-f)\b|--force-with-lease"), "force push"),
    (re.compile(r"\bsecrets\.|\bpermissions\s*:|id-token\s*:\s*write"), "secrets or token permissions"),
    (re.compile(r"(?i)\b(instance_type|desired_count|min_size|max_size|provisioned_throughput|nat_gateway)\b"), "cost-affecting resource setting"),
]


def risk_signals(files: list[FileDiff], *, mass_delete_threshold: int = 10) -> list[str]:
    """Deterministic reasons this change is high-risk. Empty list = no floor."""
    signals: list[str] = []

    def add(s):
        if s not in signals:
            signals.append(s)

    deleted = [f for f in files if f.status == "deleted"]
    if len(deleted) >= mass_delete_threshold:
        add(f"mass deletion ({len(deleted)} files)")
    for f in files:
        for pat, label in _RISKY_PATHS:
            if pat.search(f.path):
                add(f"{label}: {f.path}")
        changed = [t for _, t in f.added] + [t for _, t in f.removed]
        for pat, label in _RISKY_TEXT:
            if any(pat.search(t) for t in changed):
                add(f"{label} in {f.path}")
    return signals


# --- Branch rule -------------------------------------------------------------------

VISIBILITIES = ("public", "private-mine", "shared")


def branch_rule(*, visibility: str, target_branch: str, default_branch: str,
                via_pr: bool, risk_tier: str) -> tuple[str, str]:
    """Return ("pass" | "fail", reason). Mirrors the Lab Repo Map push rules.

    - shared:       changes reach the default branch only through a pull request.
    - public:       same, PR + review.
    - private-mine: direct to the default branch is fine for LOW risk;
                    HIGH risk must come through a pull request.
    - unknown tag:  treated as shared, the conservative default.
    """
    vis = (visibility or "").strip().lower()
    note = ""
    if vis not in VISIBILITIES:
        note = f" (visibility '{visibility or 'undeclared'}' treated as shared, the conservative default)"
        vis = "shared"
    to_default = bool(target_branch) and target_branch == default_branch
    direct = to_default and not via_pr

    if not to_default:
        return "pass", f"change targets branch '{target_branch}', not the default branch{note}"
    if not direct:
        return "pass", f"change reaches '{default_branch}' through a pull request{note}"
    if vis in ("shared", "public"):
        return "fail", (f"direct push to '{default_branch}' in a {vis} repo; "
                        f"{vis} repos take changes only through a pull request{note}")
    if risk_tier == "high":
        return "fail", (f"high-risk change pushed directly to '{default_branch}' in a private-mine repo; "
                        f"high-risk changes must go through a pull request{note}")
    return "pass", f"low-risk direct push to '{default_branch}' is allowed in a private-mine repo{note}"


# --- Repo declarations in CLAUDE.md --------------------------------------------------

_DECL = re.compile(r"(?im)^[\s>*\-]*\**(visibility|risk-floor)\**\s*:\s*\**\s*`?([a-z-]+)`?")


def parse_declarations(rules_text: str) -> dict:
    """Read `visibility: <tag>` and `risk-floor: low|high` from a CLAUDE.md.

    The recommended form is an HTML comment block, invisible when rendered:

        <!-- review-gate
        visibility: private-mine
        risk-floor: high
        -->
    """
    out: dict = {}
    for key, value in _DECL.findall(rules_text or ""):
        key = key.lower()
        value = value.lower()
        if key == "visibility" and value in VISIBILITIES and "visibility" not in out:
            out["visibility"] = value
        elif key == "risk-floor" and value in ("low", "high") and "risk_floor" not in out:
            out["risk_floor"] = value
    return out
