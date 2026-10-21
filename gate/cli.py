"""Command line for the gate.

  python -m gate local    --repo-path .  [--base main]          review a working tree before a push
  python -m gate review   --diff change.diff [--rules CLAUDE.md]  review a diff file
  python -m gate ci                                               inside GitHub Actions
  python -m gate eval     --provider openai | --offline          known-bad / known-good scores
  python -m gate providers                                        which providers have a key set

Exit codes: 0 valid, 1 not valid, 2 usage or configuration error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import ci, engine, evalsuite, gitlocal, providers, report


def _common(p):
    p.add_argument("--provider", help="openai | gemini | deepseek | grok | copilot (env REVIEW_GATE_PROVIDER)")
    p.add_argument("--model", help="override the provider's default model (env REVIEW_GATE_MODEL)")
    p.add_argument("--visibility", choices=["public", "private-mine", "shared"],
                   help="override the repo's declared visibility")
    p.add_argument("--max-diff-tokens", type=int, help="size budget for the diff (default 40000)")
    p.add_argument("--fallback", choices=["auto", "off"],
                   help="auto: if the provider gives no verdict, try other providers that have keys (default)")
    p.add_argument("--json", action="store_true", help="print the raw verdict JSON instead of Markdown")


def _limits(a):
    return {"max_diff_tokens": a.max_diff_tokens} if getattr(a, "max_diff_tokens", None) else None


def _print(v, as_json):
    if as_json:
        print(json.dumps(v, indent=2, default=str))
    else:
        print(report.to_markdown(v))


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(prog="python -m gate", description="Cross-model review gate")
    sub = ap.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("local", help="review a local working tree")
    lp.add_argument("--repo-path", default=".")
    lp.add_argument("--base", help="compare against this ref (default: the default branch)")
    lp.add_argument("--intent", default="", help="what the change is supposed to do")
    lp.add_argument("--target-branch", help="where it will be pushed (default: current branch)")
    lp.add_argument("--via-pr", action="store_true", help="it will reach the default branch by PR")
    _common(lp)

    rp = sub.add_parser("review", help="review a diff file")
    rp.add_argument("--diff", required=True, help="path to a unified diff, or - for stdin")
    rp.add_argument("--rules", help="path to the repo's CLAUDE.md")
    rp.add_argument("--repo", default="")
    rp.add_argument("--target-branch", default="main")
    rp.add_argument("--default-branch", default="main")
    rp.add_argument("--via-pr", action="store_true")
    rp.add_argument("--event", default="local")
    rp.add_argument("--intent", default="")
    _common(rp)

    cp = sub.add_parser("ci", help="run inside GitHub Actions")
    cp.add_argument("--mode", choices=["deploy", "merge"], default="deploy")
    cp.add_argument("--no-notify", action="store_true")
    cp.add_argument("--allow-bypass", action="store_true",
                    help="let the repo owner bypass when NO reviewer was available")
    _common(cp)

    ep = sub.add_parser("eval", help="score the gate on known-bad and known-good changes")
    ep.add_argument("--provider")
    ep.add_argument("--model")
    ep.add_argument("--offline", action="store_true", help="only the code-decided cases, no API calls")
    ep.add_argument("--only", help="run one case by name")
    ep.add_argument("--out", default="eval-results.json")

    sub.add_parser("providers", help="list providers and whether their key is set")

    a = ap.parse_args(argv)

    if a.cmd == "providers":
        for name, p in providers.PROVIDERS.items():
            if name == "offline":
                continue
            key = "set" if os.environ.get(p.key_env) else "NOT set"
            print(f"{name:9} model={p.default_model:18} key {p.key_env:22} {key:8} "
                  f"vision={'yes' if p.vision else 'no'}")
        return 0

    if a.cmd == "eval":
        out = evalsuite.run(provider=a.provider, model=a.model, offline=a.offline, only=a.only)
        Path(a.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(evalsuite.to_table(out))
        bad_missed = any(r["outcome"] == "MISSED" for r in out["results"])
        return 1 if bad_missed else 0

    if a.cmd == "ci":
        return ci.run(provider=a.provider, model=a.model, visibility=a.visibility,
                      limits=_limits(a), mode=a.mode, send_notifications=not a.no_notify,
                      fallback=a.fallback, allow_bypass=a.allow_bypass)

    if a.cmd == "review":
        diff = sys.stdin.read() if a.diff == "-" else Path(a.diff).read_text(encoding="utf-8", errors="replace")
        rules = Path(a.rules).read_text(encoding="utf-8", errors="replace") if a.rules else ""
        ctx = {"repo": a.repo, "target_branch": a.target_branch, "default_branch": a.default_branch,
               "via_pr": a.via_pr, "event": a.event, "intent": a.intent, "visibility": a.visibility}
        v = engine.review(diff, {"repo": rules}, ctx, provider=a.provider, model=a.model, limits=_limits(a),
                          fallback=a.fallback)
        _print(v, a.json)
        return 0 if v["verdict"] == "valid" else 1

    if a.cmd == "local":
        v = review_local(a.repo_path, base=a.base, intent=a.intent, target_branch=a.target_branch,
                         via_pr=a.via_pr, visibility=a.visibility, provider=a.provider,
                         model=a.model, limits=_limits(a), fallback=a.fallback)
        _print(v, a.json)
        return 0 if v["verdict"] == "valid" else 1
    return 2


def review_local(repo_path: str, *, base: str | None = None, intent: str = "",
                 target_branch: str | None = None, via_pr: bool = False, visibility: str | None = None,
                 provider: str | None = None, model: str | None = None, limits: dict | None = None,
                 fallback: str | None = None) -> dict:
    """Review what a local checkout would push. Shared by the CLI and the MCP tool."""
    repo = str(Path(repo_path).resolve())
    default = gitlocal.default_branch(repo)
    base = base or default
    diff = gitlocal.diff_worktree(repo, base)
    current = gitlocal.current_branch(repo)
    ctx = {"repo": gitlocal.repo_name(repo), "event": "local", "source_branch": current,
           "target_branch": target_branch or current, "default_branch": default,
           "via_pr": via_pr, "intent": intent, "visibility": visibility}
    return engine.review(diff, {"repo": gitlocal.read_rules(repo)}, ctx, provider=provider, model=model,
                         images=gitlocal.changed_images(repo, diff), limits=limits, fallback=fallback)


if __name__ == "__main__":
    sys.exit(main())
