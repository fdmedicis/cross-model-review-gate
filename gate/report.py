"""Render a verdict as Markdown: CI job summary, PR comment, blocked-deploy issue, MCP output."""

from __future__ import annotations

import json

MARKER = "<!-- cross-model-review-gate -->"

_ICON = {"pass": "✅ pass", "fail": "❌ fail"}
_LABEL = {"safety": "Safety", "correctness": "Correctness", "on_standard": "On-standard",
          "branch_rule": "Branch rule"}


def to_markdown(v: dict, *, title: str = "Review gate", footer: str = "") -> str:
    ok = v["verdict"] == "valid"
    status = v.get("meta", {}).get("status", "reviewed")
    head = {"unavailable": "⚠️ **NO REVIEWER AVAILABLE** (not valid)",
            "bypassed": "⏭️ **BYPASSED BY OWNER** (no reviewer was available)",
            "error": "❌ **GATE MISCONFIGURED** (not valid)"}.get(
        status, "✅ **VALID**" if ok else "❌ **NOT VALID**")
    meta = v.get("meta", {})
    if status in ("unavailable", "bypassed"):
        who = "none (" + ", ".join(f"{a['provider']} failed" for a in meta.get("attempts", [])) + ")"
    elif meta.get("provider"):
        who = f"{meta.get('provider')} / {meta.get('model')}"
        if meta.get("fallback_reason"):
            who += f" (fallback: {meta['fallback_reason'][:200]})"
    else:
        who = "code only (no model call)"
    lines = [
        MARKER,
        f"### {title}: {head} · risk **{v['risk_tier'].upper()}**",
        "",
        f"**What changed:** {v['what_changed']}",
        "",
        "| Check | Result |",
        "|---|---|",
    ]
    for k, label in _LABEL.items():
        lines.append(f"| {label} | {_ICON.get(v['checks'].get(k), v['checks'].get(k))} |")
    lines += ["", "**Reasons**", ""]
    lines += [f"- {r}" for r in v["reasons"]] or ["- (none given)"]
    lines += ["", f"<sub>Reviewer: {who}</sub>", ""]
    details = {k: meta[k] for k in ("risk_signals", "decided_by_code", "chain", "attempts", "fallback_skipped",
                                     "bypass", "diff_tokens", "files_reviewed", "files_not_shown_generated",
                                     "images", "other_binaries", "usage", "duration_s") if meta.get(k)}
    if details:
        lines += ["<details><summary>Details</summary>", "", "```json",
                  json.dumps(details, indent=2, default=str), "```", "</details>", ""]
    if footer:
        lines += [footer, ""]
    return "\n".join(lines)


def comparison_markdown(cmp: dict) -> str:
    if not cmp["rows"]:
        return "_No Claude verdict was given, so there is nothing to compare._"
    lines = ["| Field | Claude | Gate | |", "|---|---|---|---|"]
    for field, mine, theirs, same in cmp["rows"]:
        lines.append(f"| {field} | {mine} | {theirs} | {'agree' if same else '**DISAGREE**'} |")
    if cmp["agree"]:
        lines += ["", "Claude and the gate agree."]
    else:
        lines += ["", "**Disagreement on: " + ", ".join(cmp["disagreements"]) + ".** "
                  "Work it through before presenting: either fix the change for each gate reason "
                  "and re-run the gate, or state precisely why the gate is wrong. Then present both "
                  "views to the human owner, who decides GO / NO-GO."]
    return "\n".join(lines)
