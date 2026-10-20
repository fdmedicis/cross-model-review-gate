"""The core engine: review(diff, rules, context) -> structured verdict.

Written once, called by both entry points: the review-gate MCP tool (interactive,
during development) and the CI reusable workflow (automatic backstop on PRs and
deploys). Neither entry point adds judgment of its own.

Order of operations, and why:
  1. Parse the diff.                       (code)
  2. Secret scan.  Hit -> NOT-VALID, stop. (code; the model is never called, so a
                                            leaked secret never leaves the machine)
  3. Risk signals -> risk floor.           (code)
  4. Size budget.  Too big -> NOT-VALID.   (code; no partial reviews, no model call)
  5. Model review: safety, correctness,    (the second model)
     on-standard, risk tier.
  6. Branch rule with the final risk tier. (code)
  7. Verdict = VALID only if all four checks pass. Any error -> NOT-VALID.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import checks, diffutil, prompt, providers

VERDICT_KEYS = ("verdict", "risk_tier", "reasons", "what_changed", "checks")
CHECK_KEYS = ("safety", "correctness", "on_standard", "branch_rule")

_GLOBAL_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "global.md"


def load_global_rules() -> str:
    try:
        return _GLOBAL_RULES_PATH.read_text(encoding="utf-8")
    except OSError:
        return ""


def review(diff: str, rules: dict | str | None = None, context: dict | None = None, *,
           provider: str | None = None, model: str | None = None,
           images: dict | None = None, limits: dict | None = None) -> dict:
    """Review one change and return the verdict.

    Args:
      diff:    unified diff (`git diff` output) of the whole change.
      rules:   {"repo": <repo CLAUDE.md text>, "global": <global rules text>}, or just
               the repo CLAUDE.md text. Global rules default to rules/global.md.
      context: repo, target_branch, default_branch, via_pr (bool), event, intent,
               visibility, risk_floor. visibility / risk_floor fall back to the
               declarations in the repo CLAUDE.md, then to "shared" / none.
      provider, model: which second model reviews. Env REVIEW_GATE_PROVIDER /
               REVIEW_GATE_MODEL, then the provider default.
      images:  {path: bytes} for changed image files.
      limits:  overrides for max_diff_tokens, max_rules_tokens, max_images,
               max_image_bytes.

    Returns the contract verdict plus a `meta` block (provider, model, sizes,
    what code decided). `verdict` is "valid" only when all four checks pass.
    """
    started = time.monotonic()
    context = dict(context or {})
    limits = dict(limits or {})
    images = images or {}
    if isinstance(rules, str) or rules is None:
        rules = {"repo": rules or ""}
    repo_rules = rules.get("repo") or ""
    global_rules = rules.get("global") if rules.get("global") is not None else load_global_rules()

    decl = checks.parse_declarations(repo_rules)
    visibility = context.get("visibility") or decl.get("visibility") or ""
    risk_floor = context.get("risk_floor") or decl.get("risk_floor") or ""

    files = diffutil.parse_diff(diff or "")
    meta = {
        "engine": "cross-model-review-gate",
        "provider": None, "model": None,
        "files_changed": len(files),
        "visibility": visibility or "undeclared (treated as shared)",
        "decided_by_code": [],
    }

    def finish(model_checks, tier, reasons, what):
        b_status, b_reason = checks.branch_rule(
            visibility=visibility, target_branch=context.get("target_branch", ""),
            default_branch=context.get("default_branch", "main"),
            via_pr=bool(context.get("via_pr")), risk_tier=tier)
        all_checks = dict(model_checks, branch_rule=b_status)
        if b_status == "fail":
            reasons = [f"branch_rule: {b_reason}"] + reasons
        else:
            meta["decided_by_code"].append(f"branch_rule pass: {b_reason}")
        verdict = "valid" if all(v == "pass" for v in all_checks.values()) else "not-valid"
        meta["duration_s"] = round(time.monotonic() - started, 2)
        return {
            "verdict": verdict,
            "risk_tier": tier,
            "reasons": reasons,
            "what_changed": _audit_line(what, context, len(files)),
            "checks": {k: all_checks[k] for k in CHECK_KEYS},
            "meta": meta,
        }

    failed = {"safety": "fail", "correctness": "fail", "on_standard": "fail"}

    if not files:
        meta["decided_by_code"].append("empty diff: nothing to review")
        return finish({"safety": "pass", "correctness": "pass", "on_standard": "pass"},
                      "low", ["No changes to review."], "no file changes")

    # 2. Secrets: fail before anything leaves the machine.
    secrets = checks.scan_secrets(files)
    signals = checks.risk_signals(files)
    tier_floor = "high" if (signals or risk_floor == "high") else "low"
    if risk_floor == "high":
        signals = ["repo declares risk-floor: high"] + signals
    meta["risk_signals"] = signals
    if secrets:
        meta["secret_findings"] = [s.__dict__ for s in secrets]
        meta["decided_by_code"].append("secret scan failed: model not called")
        reasons = [f"safety: possible secret ({s.rule}) in {s.path}"
                   + (f" at diff line {s.diff_line}" if s.diff_line else "") + f": {s.preview}"
                   for s in secrets]
        reasons.append("The review model was not called, so the secret was not sent anywhere. "
                       "Remove it, rotate it if it was ever pushed, and re-run.")
        return finish({"safety": "fail", "correctness": "fail", "on_standard": "fail"},
                      "high", reasons, "change contains a possible secret")

    # 4. Size budget.
    rules_text = (global_rules or "") + (repo_rules or "")
    budget = diffutil.plan_budget(
        files, rules_tokens=diffutil.estimate_tokens(rules_text),
        max_diff_tokens=int(limits.get("max_diff_tokens") or diffutil.DEFAULT_MAX_DIFF_TOKENS),
        max_rules_tokens=int(limits.get("max_rules_tokens") or diffutil.DEFAULT_MAX_RULES_TOKENS),
        max_images=int(limits.get("max_images") or diffutil.DEFAULT_MAX_IMAGES),
        max_image_bytes=int(limits.get("max_image_bytes") or diffutil.DEFAULT_MAX_IMAGE_BYTES),
        image_sizes={p: len(b) for p, b in images.items()})
    meta.update(diff_tokens=budget.diff_tokens,
                files_reviewed=[f.path for f in budget.reviewable],
                files_not_shown_generated=[f.path for f in budget.generated],
                images=[f.path for f in budget.images],
                other_binaries=[f.path for f in budget.other_binary])
    if budget.oversize_reasons:
        meta["decided_by_code"].append("size budget exceeded: model not called")
        return finish(failed, tier_floor, budget.oversize_reasons + [
            "The gate does not review part of a change: a partial review would pass what it never saw."],
            "change too large to review")

    missing_images = [f.path for f in budget.images if f.path not in images]
    if missing_images:
        meta["decided_by_code"].append("image bytes unavailable")
        return finish(failed, tier_floor,
                      [f"safety: image {p} changed but its content was not provided to the gate"
                       for p in missing_images], "image change could not be inspected")

    other_bins = budget.other_binary
    if other_bins:
        signals.append("binary files that cannot be reviewed: " + ", ".join(f.path for f in other_bins))
        meta["risk_signals"] = signals
        tier_floor = "high"

    # 5. Model review.
    try:
        p, m = providers.resolve(provider, model)
    except providers.ConfigError as e:
        meta["decided_by_code"].append("provider misconfigured")
        return finish(failed, tier_floor, [f"gate error: {e}"], "review provider misconfigured")
    meta.update(provider=p.name, model=m)

    diff_text = checks.redact_secrets("".join(f.text for f in budget.reviewable))
    model_context = {
        "repo": context.get("repo"), "event": context.get("event"),
        "target_branch": context.get("target_branch"), "default_branch": context.get("default_branch"),
        "via_pull_request": context.get("via_pr"), "visibility": visibility or "undeclared",
        "intent": context.get("intent"),
    }
    user_msg = prompt.build_user_message(
        diff_text=diff_text, repo_rules=repo_rules, global_rules=global_rules,
        context=model_context, skipped=[f.path for f in budget.generated],
        images=[f.path for f in budget.images], risk_floor_reasons=signals)
    try:
        raw, call_meta = providers.call(p, m, prompt.SYSTEM_PROMPT, user_msg,
                                        images=[(f.path, images[f.path]) for f in budget.images])
        meta.update(call_meta)
        if call_meta.get("model_used"):
            meta["model"] = call_meta["model_used"]     # the model that actually reviewed
        parsed = prompt.validate_model_output(prompt.extract_json(raw))
    except (providers.ProviderError, prompt.ModelOutputError) as e:
        meta["decided_by_code"].append("review failed closed")
        return finish(failed, tier_floor, [f"gate error: {e}",
                      "The gate fails closed: no review means not valid."], "review could not be completed")

    tier = "high" if "high" in (parsed["risk_tier"], tier_floor) else "low"
    reasons = parsed["reasons"] or ["The review model gave no reasons."]
    if parsed["risk_tier"] == "low" and tier == "high":
        meta["decided_by_code"].append(
            f"risk tier raised from low to high by code ({len(signals)} risk signal(s), see risk_signals)")
    return finish(parsed["checks"], tier, reasons, parsed["what_changed"])


def _audit_line(what: str, context: dict, n_files: int) -> str:
    repo = context.get("repo") or "local repo"
    target = context.get("target_branch") or "?"
    how = "via pull request" if context.get("via_pr") else (
        "direct push" if context.get("event") in ("push", "local") else context.get("event") or "")
    source = context.get("source_branch")
    route = f"{source} -> {target}" if source and source != target else target
    return f"{what.rstrip('.')}. [{repo} @ {route}, {how}, {n_files} file(s)]"


def compare(claude: dict, gate: dict) -> dict:
    """Compare Claude's own verdict with the gate's, check by check.

    Claude's verdict may be partial; anything it left out is not compared.
    Disagreements are what the interactive loop is for.
    """
    rows, disagreements = [], []
    for key in ("verdict", "risk_tier"):
        if key in claude:
            same = str(claude[key]).lower() == str(gate.get(key, "")).lower()
            rows.append((key, claude[key], gate.get(key), same))
            if not same:
                disagreements.append(key)
    for key in CHECK_KEYS:
        mine = (claude.get("checks") or {}).get(key)
        if mine is None:
            continue
        theirs = gate.get("checks", {}).get(key)
        same = str(mine).lower() == str(theirs).lower()
        rows.append((f"checks.{key}", mine, theirs, same))
        if not same:
            disagreements.append(f"checks.{key}")
    return {"agree": not disagreements, "disagreements": disagreements, "rows": rows}
