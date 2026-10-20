"""Unified-diff parsing and the size budget.

Everything here is deterministic: no model is involved. The engine uses it to
decide WHAT the model gets to see, and to refuse a review that would be partial.
"""

from __future__ import annotations

import fnmatch
import math
import re
from dataclasses import dataclass, field

# Files whose diffs are machine-generated. They are secret-scanned and still count
# as "changed" for the risk signals, but their text is not sent to the model:
# reviewing a lockfile line by line adds cost and noise, never judgment.
GENERATED_PATTERNS = (
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lock", "bun.lockb", "poetry.lock", "Pipfile.lock", "uv.lock",
    "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock",
    ".terraform.lock.hcl",
    "*.min.js", "*.min.css", "*.map",
)

IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".webp")

# Defaults for the size budget. See README "Oversized diffs" for the reasoning.
DEFAULT_MAX_DIFF_TOKENS = 40_000
DEFAULT_MAX_RULES_TOKENS = 12_000
DEFAULT_MAX_IMAGES = 4
DEFAULT_MAX_IMAGE_BYTES = 3 * 1024 * 1024


def estimate_tokens(text: str) -> int:
    """Rough token count: ~4 characters per token for code and English.

    Deliberately simple and provider-independent. It only has to be good enough
    to decide "fits" versus "too large", and it errs a little high on code.
    """
    return math.ceil(len(text) / 4)


@dataclass
class FileDiff:
    path: str
    old_path: str = ""
    status: str = "modified"          # added | deleted | modified | renamed
    binary: bool = False
    text: str = ""                    # the full diff text for this file
    added: list = field(default_factory=list)    # (diff_line_no, text) of '+' lines
    removed: list = field(default_factory=list)  # (diff_line_no, text) of '-' lines

    @property
    def is_image(self) -> bool:
        return self.path.lower().endswith(IMAGE_EXTENSIONS)

    @property
    def is_generated(self) -> bool:
        name = self.path.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(name, pat) for pat in GENERATED_PATTERNS)

    @property
    def tokens(self) -> int:
        return estimate_tokens(self.text)


_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+)$")


def parse_diff(diff: str) -> list[FileDiff]:
    """Split a `git diff` into per-file pieces.

    Handles additions, deletions, renames, mode changes and binary markers.
    Text that is not inside a `diff --git` section is ignored.
    """
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    lines: list[str] = []

    def close():
        if cur is not None:
            cur.text = "\n".join(lines) + "\n"
            files.append(cur)

    for i, line in enumerate(diff.splitlines(), start=1):
        m = _HEADER.match(line)
        if m:
            close()
            cur = FileDiff(path=m.group(2), old_path=m.group(1))
            lines = [line]
            continue
        if cur is None:
            continue
        lines.append(line)
        if line.startswith("new file mode"):
            cur.status = "added"
        elif line.startswith("deleted file mode"):
            cur.status = "deleted"
        elif line.startswith("rename from "):
            cur.status = "renamed"
        elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            cur.binary = True
        elif line.startswith("+++ ") or line.startswith("--- "):
            pass
        elif line.startswith("+"):
            cur.added.append((i, line[1:]))
        elif line.startswith("-"):
            cur.removed.append((i, line[1:]))
    close()
    return files


@dataclass
class Budget:
    reviewable: list            # FileDiff sent to the model as text
    generated: list             # FileDiff skipped as machine-generated
    images: list                # FileDiff that are images (sent as images when possible)
    other_binary: list          # binaries that are neither images nor reviewable
    diff_tokens: int            # estimated tokens of the reviewable text
    oversize_reasons: list      # empty when the change fits


def plan_budget(files: list[FileDiff], *, rules_tokens: int,
                max_diff_tokens: int = DEFAULT_MAX_DIFF_TOKENS,
                max_rules_tokens: int = DEFAULT_MAX_RULES_TOKENS,
                max_images: int = DEFAULT_MAX_IMAGES,
                image_sizes: dict | None = None,
                max_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES) -> Budget:
    """Decide what the model sees, and whether the change is too large to review.

    Never truncates. A change either fits whole or is refused with the numbers
    that explain why, so the author knows what to split.
    """
    image_sizes = image_sizes or {}
    reviewable, generated, images, other_binary = [], [], [], []
    for f in files:
        if f.is_image and f.status != "deleted":
            images.append(f)
        elif f.binary:
            other_binary.append(f)
        elif f.is_generated:
            generated.append(f)
        else:
            reviewable.append(f)

    diff_tokens = sum(f.tokens for f in reviewable)
    reasons = []
    if diff_tokens > max_diff_tokens:
        largest = sorted(reviewable, key=lambda f: f.tokens, reverse=True)[:5]
        detail = ", ".join(f"{f.path} (~{f.tokens:,})" for f in largest)
        reasons.append(
            f"Too large to review: ~{diff_tokens:,} tokens of diff, limit is {max_diff_tokens:,}. "
            f"Largest files: {detail}. Split the change into smaller pull requests, "
            f"or raise max_diff_tokens for this repo."
        )
    if rules_tokens > max_rules_tokens:
        reasons.append(
            f"Repo rules too long: ~{rules_tokens:,} tokens, limit is {max_rules_tokens:,}. "
            f"Shorten CLAUDE.md; the gate will not review against rules it cannot read whole."
        )
    if len(images) > max_images:
        reasons.append(
            f"Too many images to review: {len(images)}, limit is {max_images}. "
            f"Split the change so each part adds at most {max_images} images."
        )
    for f in images:
        size = image_sizes.get(f.path)
        if size is not None and size > max_image_bytes:
            reasons.append(
                f"Image too large to review: {f.path} is {size / 1_048_576:.1f} MB, "
                f"limit is {max_image_bytes / 1_048_576:.0f} MB. Compress it first."
            )
    return Budget(reviewable, generated, images, other_binary, diff_tokens, reasons)
