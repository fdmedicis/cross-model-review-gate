"""Build the review input from a git checkout: the diff, the rules, changed images.

Used by both entry points: the MCP tool (a working tree before a push) and CI
(two commits from the GitHub event).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .diffutil import IMAGE_EXTENSIONS, parse_diff

# No --binary: image bytes are fetched separately (changed_images), so binary
# patches would only bloat the diff text.
_DIFF_FLAGS = ["--no-color", "--no-ext-diff", "-M"]


def git(repo: str, *args: str, binary: bool = False, check: bool = True):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, check=False)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.decode('utf-8', 'replace').strip()}")
    return r.stdout if binary else r.stdout.decode("utf-8", "replace")


def default_branch(repo: str) -> str:
    ref = git(repo, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD", check=False).strip()
    if ref.startswith("origin/"):
        return ref.split("/", 1)[1]
    for name in ("main", "master"):
        if git(repo, "rev-parse", "--verify", "--quiet", name, check=False).strip():
            return name
    return "main"


def current_branch(repo: str) -> str:
    # symbolic-ref also works in a repo with no commits yet (rev-parse says "HEAD").
    name = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD", check=False).strip()
    return name or git(repo, "rev-parse", "--short", "HEAD", check=False).strip() or "HEAD"


def repo_name(repo: str) -> str:
    url = git(repo, "remote", "get-url", "origin", check=False).strip()
    if url:
        tail = url.rstrip("/").removesuffix(".git").replace(":", "/").split("/")
        return "/".join(tail[-2:])
    return Path(repo).resolve().name


EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def diff_range(repo: str, base: str, head: str) -> str:
    """Diff between two commits (CI). `base...head` = changes on head since they diverged.
    Against the empty tree (first push of a repo) there is no merge base, so two-dot."""
    if base == EMPTY_TREE:
        return git(repo, "diff", *_DIFF_FLAGS, base, head)
    return git(repo, "diff", *_DIFF_FLAGS, f"{base}...{head}")


def diff_worktree(repo: str, base: str) -> str:
    """Everything that would be pushed: commits since `base`, staged and unstaged
    edits, and new untracked files (minus ignored ones). Nothing is staged or changed."""
    if not git(repo, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}", check=False).strip():
        base = EMPTY_TREE          # unborn repo or unknown base: everything is new
        merge_base = EMPTY_TREE
    else:
        merge_base = git(repo, "merge-base", base, "HEAD", check=False).strip() or base
    out = git(repo, "diff", *_DIFF_FLAGS, merge_base)
    untracked = [p for p in git(repo, "ls-files", "--others", "--exclude-standard", "-z").split("\0") if p]
    for path in untracked:
        r = subprocess.run(["git", "-C", repo, "diff", *_DIFF_FLAGS, "--no-index", "--", os.devnull, path],
                           capture_output=True)
        # --no-index exits 1 when files differ, which is the normal case here.
        chunk = r.stdout.decode("utf-8", "replace")
        out += chunk.replace(f"a/{os.devnull}", f"a/{path}").replace(f"b/{os.devnull}", f"b/{path}")
    return out


def read_rules(repo: str, ref: str | None = None) -> str:
    """The repo's CLAUDE.md (root, then .claude/CLAUDE.md), at `ref` or in the working tree.

    CI reads it at the BASE commit, so a pull request cannot loosen the rules it is
    judged against. Rule changes are themselves flagged high-risk by the engine.
    """
    texts = []
    for rel in ("CLAUDE.md", ".claude/CLAUDE.md"):
        if ref:
            t = git(repo, "show", f"{ref}:{rel}", check=False)
        else:
            p = Path(repo) / rel
            t = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""
        if t.strip():
            texts.append(f"# {rel}\n{t}")
    return "\n\n".join(texts)


def changed_images(repo: str, diff: str, ref: str | None = None) -> dict:
    """{path: bytes} for images added or modified by the diff, at `ref` or on disk."""
    out = {}
    for f in parse_diff(diff):
        if f.status == "deleted" or not f.path.lower().endswith(IMAGE_EXTENSIONS):
            continue
        if ref:
            data = git(repo, "show", f"{ref}:{f.path}", binary=True, check=False)
        else:
            p = Path(repo) / f.path
            data = p.read_bytes() if p.is_file() else b""
        if data:
            out[f.path] = data
    return out
