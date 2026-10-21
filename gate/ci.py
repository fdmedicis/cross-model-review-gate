"""CI entry point: run the engine inside GitHub Actions.

Reads the GitHub event, builds the diff for the change, runs the same engine the
MCP tool uses, then reports:
  - job summary (always)
  - step outputs `verdict` and `risk_tier` (always)
  - pull request: one sticky comment with the verdict, updated on every push
  - push / manual run that is NOT valid: an issue assigned to the repo owner
    saying the deploy was blocked, so the block is never silent
Exit code 0 = valid, 1 = not valid. A failing job is what blocks the merge
(required status check) or the deploy (`needs:` on the deploy job).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
import os
import urllib.error
import urllib.request

from . import engine, gitlocal, report

EMPTY_TREE = gitlocal.EMPTY_TREE
ZERO_SHA = "0" * 40


def _api(method: str, path: str, token: str, body: dict | None = None):
    url = os.environ.get("GITHUB_API_URL", "https://api.github.com") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "cross-model-review-gate"})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def _merged_via_pr(repo: str, sha: str, target: str, token: str) -> tuple[bool, str]:
    """Was this pushed commit merged through a pull request into `target`?"""
    if not token:
        return False, "no GITHUB_TOKEN, so treated as a direct push"
    try:
        pulls = _api("GET", f"/repos/{repo}/commits/{sha}/pulls", token) or []
    except urllib.error.URLError as e:
        return False, f"could not look up pull requests ({e}), so treated as a direct push"
    for pr in pulls:
        if pr.get("merged_at") and pr.get("base", {}).get("ref") == target:
            return True, f"merged through pull request #{pr['number']}"
    return False, "no merged pull request contains this commit"


def _epoch_iso(value) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value or "")


def _ts(value: str):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def event_context(repo_dir: str = ".") -> dict:
    """Turn the GitHub event into base/head commits and engine context."""
    name = os.environ.get("GITHUB_EVENT_NAME", "")
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
        ev = json.load(fh)
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    default = (ev.get("repository") or {}).get("default_branch") or "main"

    if name in ("pull_request", "pull_request_target"):
        pr = ev["pull_request"]
        return {
            "base": pr["base"]["sha"], "head": pr["head"]["sha"], "rules_ref": pr["base"]["sha"],
            "pr_number": pr["number"], "triggered_at": pr.get("updated_at") or "",
            "context": {"repo": repo, "event": "pull_request", "target_branch": pr["base"]["ref"],
                        "source_branch": pr["head"]["ref"], "default_branch": default, "via_pr": True,
                        "intent": (pr.get("title") or "") + "\n\n" + (pr.get("body") or "")},
        }
    if name in ("push", "workflow_dispatch"):
        head = ev.get("after") or os.environ.get("GITHUB_SHA", "")
        base = ev.get("before", "")
        if not base or base == ZERO_SHA:
            has_parent = gitlocal.git(repo_dir, "rev-parse", "--verify", "--quiet", f"{head}~1",
                                      check=False).strip()
            base = f"{head}~1" if has_parent else EMPTY_TREE
        target = os.environ.get("GITHUB_REF_NAME", "")
        via_pr, why = _merged_via_pr(repo, head, target, token)
        intent = ((ev.get("head_commit") or {}).get("message") or "") if name == "push" else "manual run"
        return {
            "base": base, "head": head, "rules_ref": base if base != EMPTY_TREE else None,
            "pr_number": None, "via_pr_reason": why,
            "triggered_at": _epoch_iso((ev.get("repository") or {}).get("pushed_at")) if name == "push" else "",
            "context": {"repo": repo, "event": "push" if name == "push" else "workflow_dispatch",
                        "target_branch": target, "default_branch": default, "via_pr": via_pr,
                        "intent": intent},
        }
    raise SystemExit(f"review-gate: unsupported event '{name}' (use pull_request, push or workflow_dispatch)")


def _write(path_env: str, text: str):
    path = os.environ.get(path_env)
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)


BYPASS_LABEL = "review-gate-bypass"


def _merged_pr_number(repo: str, sha: str, target: str, token: str):
    pulls = []
    try:
        for page in range(1, 6):
            batch = _api("GET", f"/repos/{repo}/commits/{sha}/pulls?per_page=100&page={page}", token) or []
            pulls += batch
            if len(batch) < 100:
                break
    except urllib.error.URLError:
        return None
    for pr in pulls:
        if pr.get("merged_at") and pr.get("base", {}).get("ref") == target:
            return pr["number"]
    return None


def _label_added_by_owner(repo: str, number: int, token: str, owner: str,
                          since: str) -> tuple[bool, str]:
    try:
        labels = _api("GET", f"/repos/{repo}/issues/{number}/labels", token) or []
        if BYPASS_LABEL not in [lb.get("name") for lb in labels]:
            return False, f"label {BYPASS_LABEL} is not on pull request #{number}"
        # Every page, so the LATEST "labeled" event is the one judged. Events come oldest
        # first. If there are too many to read completely, refuse (fail closed).
        events = []
        for page in range(1, 11):
            batch = _api("GET", f"/repos/{repo}/issues/{number}/events?per_page=100&page={page}", token) or []
            events += batch
            if len(batch) < 100:
                break
        else:
            return False, f"pull request #{number} has too many events to verify who added the label"
    except urllib.error.URLError as e:
        return False, f"could not read the labels of pull request #{number} ({e})"
    added = [e for e in events if e.get("event") == "labeled"
             and (e.get("label") or {}).get("name") == BYPASS_LABEL]
    who = (added[-1].get("actor") or {}).get("login") if added else None
    if who != owner:
        return False, f"label {BYPASS_LABEL} on #{number} was added by {who or 'unknown'}, not the owner {owner}"
    # Bind the approval to THIS change: the label must postdate the run it bypasses,
    # so a leftover or pre-emptive label never covers commits the owner has not seen.
    added_at, since_at = _ts(added[-1].get("created_at", "")), _ts(since)
    if not since_at or not added_at or added_at <= since_at:
        return False, (f"label {BYPASS_LABEL} on #{number} was added before this run was triggered "
                       f"({added[-1].get('created_at') or 'unknown'} vs {since or 'unknown'}); "
                       "add it again after the failed run, then re-run")
    return True, f"label {BYPASS_LABEL} on pull request #{number}, added by the owner ({owner})"


def owner_bypass(ev: dict) -> tuple[bool, str]:
    """Did the repo owner approve, IN A PULL REQUEST, going ahead without a review?

    Only consulted when NO reviewer could produce a verdict and the caller opted in.
    The approval is always the label `review-gate-bypass` added by the owner:
    - pull_request event: on that pull request;
    - push / manual run: on the merged pull request that brought the commit in.
      A direct push, with no pull request, can never be bypassed.
    """
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "")
    if not owner or not token:
        return False, "repository owner or GITHUB_TOKEN unknown"
    number = ev.get("pr_number")
    if not number:
        number = _merged_pr_number(repo, ev.get("head") or "", ev["context"].get("target_branch", ""), token)
        if not number:
            return False, "no merged pull request contains this commit; a direct push cannot be bypassed"
    return _label_added_by_owner(repo, number, token, owner, ev.get("triggered_at", ""))


def _bypass_how(ev: dict) -> str:
    where = "this pull request" if ev.get("pr_number") else "the merged pull request that brought this commit in"
    return (f"The owner can let this through without a review: add the label `{BYPASS_LABEL}` "
            f"to {where} (after this run, so it covers exactly this change), then re-run the failed gate job.")


def notify(verdict: dict, ev: dict, *, mode: str, bypass_allowed: bool = False) -> list[str]:
    """PR: sticky comment. Push/dispatch that is not valid: open an issue for the owner."""
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{repo}"
               f"/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}")
    owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "")
    status = verdict["meta"].get("status", "reviewed")
    done = []
    if not token:
        return ["no GITHUB_TOKEN: notifications skipped"]
    try:
        if ev.get("pr_number"):
            blocked = verdict["verdict"] != "valid" and status != "bypassed"
            if status == "bypassed":
                outcome = f"**Bypassed by the owner**: {verdict['meta'].get('bypass', '')}. No reviewer saw this change."
            elif status == "unavailable":
                outcome = ("**No reviewer was available**, so this pull request cannot merge yet. "
                           + (_bypass_how(ev) if bypass_allowed else
                              "Add a fallback provider key to this repo, or wait until the reviewer is available."))
            elif blocked:
                outcome = ("This pull request **must not merge** as it is." if mode == "merge"
                           else "Merging this as it is would be **blocked at deploy**.")
            else:
                outcome = "The gate has no objection."
            body = report.to_markdown(verdict, title="Review gate", footer=f"[Gate run]({run_url}) · {outcome}")
            comments = _api("GET", f"/repos/{repo}/issues/{ev['pr_number']}/comments?per_page=100", token) or []
            mine = [c for c in comments if report.MARKER in (c.get("body") or "")]
            if mine:
                _api("PATCH", f"/repos/{repo}/issues/comments/{mine[-1]['id']}", token, {"body": body})
                done.append("updated the pull request comment")
            else:
                _api("POST", f"/repos/{repo}/issues/{ev['pr_number']}/comments", token, {"body": body})
                done.append("commented on the pull request")
        elif verdict["verdict"] != "valid" and status != "bypassed":
            short = (ev.get("head") or "")[:7]
            branch = ev["context"].get("target_branch")
            if status == "unavailable":
                title = f"[review-gate] No reviewer available, deploy not run: {short} on {branch}"
                how = (_bypass_how(ev) if bypass_allowed else
                       "To deploy: add a fallback provider key to this repo, or re-run once the reviewer is available.")
            else:
                title = f"[review-gate] Deploy blocked: {short} on {branch}"
                how = "To deploy: fix the change and push again, or split it if it was too large."
            footer = (f"@{owner} the deploy for `{short}` was **not run**. [Gate run]({run_url}).\n\n"
                      f"{how} Close this issue once it is resolved.")
            body = report.to_markdown(verdict, title="Deploy blocked by the review gate", footer=footer)
            payload = {"title": title, "body": body}
            if owner:
                payload["assignees"] = [owner]
            try:
                issue = _api("POST", f"/repos/{repo}/issues", token, payload)
            except urllib.error.HTTPError:
                payload.pop("assignees", None)       # owner not assignable: still open the issue
                issue = _api("POST", f"/repos/{repo}/issues", token, payload)
            done.append(f"opened issue #{issue['number']} for {owner or 'the owner'}")
    except urllib.error.HTTPError as e:
        done.append(f"notification failed: HTTP {e.code} (does the caller grant "
                    f"pull-requests: write and issues: write?)")
    except urllib.error.URLError as e:
        done.append(f"notification failed: {e}")
    return done


def apply_bypass(verdict: dict, ev: dict, *, allow: bool, repo_dir: str = ".") -> None:
    """Turn an 'unavailable' result into 'bypassed' when allowed and the owner approved.

    Never for a real verdict, never for a misconfigured gate, never when the branch rule
    (a code-decided fact) failed."""
    if verdict["meta"].get("status") != "unavailable" or not allow:
        return
    if verdict["checks"].get("branch_rule") != "pass":
        verdict["meta"]["bypass_refused"] = "the branch rule failed; a bypass only covers a missing reviewer"
        return
    ok, why = owner_bypass(ev)
    if ok:
        verdict["meta"]["status"] = "bypassed"
        verdict["meta"]["bypass"] = why
        verdict["reasons"].insert(0, f"BYPASSED: {why}. No reviewer saw this change.")
    else:
        verdict["meta"]["bypass_not_applied"] = why


def run(*, repo_dir: str = ".", provider: str | None = None, model: str | None = None,
        visibility: str | None = None, limits: dict | None = None, mode: str = "deploy",
        send_notifications: bool = True, fallback: str | None = None,
        allow_bypass: bool = False) -> int:
    ev = event_context(repo_dir)
    ctx = ev["context"]
    if visibility:
        ctx["visibility"] = visibility
    diff = gitlocal.diff_range(repo_dir, ev["base"], ev["head"])
    rules = gitlocal.read_rules(repo_dir, ev["rules_ref"]) if ev["rules_ref"] else ""
    images = gitlocal.changed_images(repo_dir, diff, ref=ev["head"])

    verdict = engine.review(diff, {"repo": rules}, ctx, provider=provider, model=model,
                            images=images, limits=limits, fallback=fallback)
    if ev.get("via_pr_reason"):
        verdict["meta"]["via_pr"] = ev["via_pr_reason"]
    apply_bypass(verdict, ev, allow=allow_bypass, repo_dir=repo_dir)

    with open("review-gate-verdict.json", "w", encoding="utf-8") as fh:
        json.dump(verdict, fh, indent=2, default=str)
    sent = (notify(verdict, ev, mode=mode, bypass_allowed=allow_bypass) if send_notifications
            else ["notifications disabled"])
    verdict["meta"]["notifications"] = sent

    _write("GITHUB_STEP_SUMMARY", report.to_markdown(verdict) + "\n")
    _write("GITHUB_OUTPUT", f"verdict={verdict['verdict']}\nstatus={verdict['meta']['status']}\n"
                            f"risk_tier={verdict['risk_tier']}\n")
    print(json.dumps({k: verdict[k] for k in engine.VERDICT_KEYS}, indent=2))
    print("notifications:", "; ".join(sent))
    return 0 if verdict["verdict"] == "valid" or verdict["meta"]["status"] == "bypassed" else 1
