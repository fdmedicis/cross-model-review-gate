# CLAUDE.md — cross-model-review-gate

<!-- review-gate
visibility: public
risk-floor: high
-->

This repo is the governor: the code that decides whether AI-written changes in
other repos may merge or deploy. A bug here weakens every protected repo at once.

## Rules
- **Public repo: every change goes through a pull request and review.** Releases
  are tagged (`v1`, `v1.x.y`); callers pin the major tag.
- **Fail closed, always.** Any new code path that can error must end in
  `not-valid`, never in `valid` or an exception that a caller could read as success.
  **One deliberate exception, decided by the owner:** the opt-in owner bypass. When
  no reviewer could produce a verdict (`meta.status: unavailable`) and the repo set
  `allow_bypass_when_unavailable`, the owner's `review-gate-bypass` label on the pull
  request lets the job succeed. This is the owner's explicit approval in the pull
  request that the global rules require for skipping the gate. It never applies to a
  real verdict, a misconfigured gate or a failed code check, the verdict stays
  `not-valid`, and the result is marked `bypassed` and published.
- **Code decides what code can decide.** Secrets, branch rule, risk floor and size
  stay deterministic. Do not move them into the prompt.
- **No secrets, ever,** including in tests. Fixture secrets are assembled at
  runtime so no secret-looking string is committed.
- **Standard library only.** The gate runs in CI with no `pip install`.
- **Never weaken the eval suite to make a change pass.** If a known-bad case stops
  being caught, that is a regression, not a test to delete.
- Keep the verdict schema stable within a major version.

## Before a pull request
1. `python -m unittest discover -s tests -v`
2. `python -m gate eval --offline`
3. If the prompt or a provider changed: `python -m gate eval --provider <p>` and put
   the catch rate and false positives in the PR description.
