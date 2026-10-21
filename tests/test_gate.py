"""Offline tests: everything that does not need a real model.

Run: python -m unittest discover -s tests -v
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gate import checks, ci, diffutil, engine, evalsuite, gitlocal, prompt, providers, report  # noqa: E402

D = evalsuite._file_diff


class DiffParsing(unittest.TestCase):
    def test_statuses_and_lines(self):
        diff = (D("a.py", ["x = 1"], new=True) + D("b.py", ["y = 2"], ["y = 1"])
                + evalsuite._binary_diff("img/p.png")
                + "diff --git a/old.txt b/new.txt\nsimilarity index 100%\nrename from old.txt\nrename to new.txt\n")
        files = {f.path: f for f in diffutil.parse_diff(diff)}
        self.assertEqual(files["a.py"].status, "added")
        self.assertEqual(files["b.py"].status, "modified")
        self.assertEqual([t for _, t in files["b.py"].added], ["y = 2"])
        self.assertEqual([t for _, t in files["b.py"].removed], ["y = 1"])
        self.assertTrue(files["img/p.png"].binary and files["img/p.png"].is_image)
        self.assertEqual(files["new.txt"].status, "renamed")

    def test_generated_files_skipped_not_counted(self):
        files = diffutil.parse_diff(D("package-lock.json", ["x"] * 5000) + D("app.py", ["print(1)"]))
        b = diffutil.plan_budget(files, rules_tokens=10)
        self.assertEqual([f.path for f in b.generated], ["package-lock.json"])
        self.assertEqual([f.path for f in b.reviewable], ["app.py"])
        self.assertFalse(b.oversize_reasons)

    def test_oversize_names_numbers_and_files(self):
        files = diffutil.parse_diff(D("big.py", ["a = 1  # padding padding padding"] * 6000))
        b = diffutil.plan_budget(files, rules_tokens=10, max_diff_tokens=1000)
        self.assertEqual(len(b.oversize_reasons), 1)
        msg = b.oversize_reasons[0]
        self.assertIn("limit is 1,000", msg)
        self.assertIn("big.py", msg)

    def test_too_many_and_too_big_images(self):
        diff = "".join(evalsuite._binary_diff(f"i{n}.png") for n in range(6))
        b = diffutil.plan_budget(diffutil.parse_diff(diff), rules_tokens=0,
                                 image_sizes={"i0.png": 10 * 1024 * 1024})
        text = " ".join(b.oversize_reasons)
        self.assertIn("Too many images", text)
        self.assertIn("i0.png is 10.0 MB", text)


class Secrets(unittest.TestCase):
    def scan(self, *added, path="app/x.py"):
        return checks.scan_secrets(diffutil.parse_diff(D(path, list(added), new=True)))

    def test_detects_common_secrets(self):
        samples = {
            "aws-access-key-id": "AKIA" + "Q7XW2M9KLP4ZT3RB",
            "github-token": "ghp_" + "a1B2" * 9,
            "openai-key": "sk-proj-" + "Zx9" * 12,
            "private-key-block": "-----BEGIN RSA " + "PRIVATE KEY-----",
            "password-or-token-assignment": 'password = "' + "S3cure!" * 3 + '"',
        }
        for rule, text in samples.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, [f.rule for f in self.scan(text)])

    def test_preview_never_contains_the_value(self):
        key = "AKIA" + "Q7XW2M9KLP4ZT3RB"
        f = self.scan(f'k = "{key}"')[0]
        self.assertNotIn(key[:6], f.preview)

    def test_placeholders_and_env_example_pass(self):
        self.assertEqual(self.scan('API_TOKEN="your-token-here"', path=".env.example"), [])
        self.assertEqual(self.scan('token = "${{ secrets.DEPLOY_TOKEN }}"', 'k = os.environ["API_KEY"]'), [])

    def test_env_file_flagged(self):
        self.assertEqual([f.rule for f in self.scan("DEBUG=1", path=".env")], ["env-file-committed"])
        self.assertEqual([f.rule for f in self.scan("DEBUG=1", path="config/local.env")], ["env-file-committed"])

    def test_redaction(self):
        self.assertNotIn("Q7XW", checks.redact_secrets("id AKIA" + "Q7XW2M9KLP4ZT3RB end"))

    def test_redaction_leaves_placeholders(self):
        # Found by the first live eval: redacting a placeholder made the reviewer suspect a secret.
        text = 'PASSWORD="changeme-please"\nAPI_TOKEN="your-token-here"'
        self.assertEqual(checks.redact_secrets(text), text)
        self.assertIn("REDACTED", checks.redact_secrets('password = "' + "S3cure!" * 3 + '"'))


class RiskAndBranch(unittest.TestCase):
    def test_risk_signals(self):
        cases = {
            ".github/workflows/x.yml": (["- run: echo"], "CI/CD"),
            "main.tf": (['resource "aws_iam_role" "r" {'], "IAM"),
            "deploy.sh": (["rm -rf /var/data"], "destructive command"),
            "README.md": (["hello"], None),
        }
        for path, (lines, expect) in cases.items():
            with self.subTest(path=path):
                sig = " ".join(checks.risk_signals(diffutil.parse_diff(D(path, lines))))
                if expect:
                    self.assertIn(expect, sig)
                else:
                    self.assertEqual(sig, "")

    def test_branch_matrix(self):
        def br(vis, via_pr, tier="low", target="main"):
            return checks.branch_rule(visibility=vis, target_branch=target, default_branch="main",
                                      via_pr=via_pr, risk_tier=tier)[0]
        self.assertEqual(br("shared", False), "fail")
        self.assertEqual(br("shared", True), "pass")
        self.assertEqual(br("public", False), "fail")
        self.assertEqual(br("private-mine", False, "low"), "pass")
        self.assertEqual(br("private-mine", False, "high"), "fail")
        self.assertEqual(br("private-mine", True, "high"), "pass")
        self.assertEqual(br("", False), "fail")                      # undeclared = shared
        self.assertEqual(br("shared", False, target="feature"), "pass")

    def test_declarations(self):
        text = "# x\n<!-- review-gate\nvisibility: private-mine\nrisk-floor: high\n-->\n"
        self.assertEqual(checks.parse_declarations(text), {"visibility": "private-mine", "risk_floor": "high"})
        self.assertEqual(checks.parse_declarations("- **Visibility:** `public`"), {"visibility": "public"})
        self.assertEqual(checks.parse_declarations("visibility: secret-ish"), {})


class ModelOutput(unittest.TestCase):
    good = {"checks": {"safety": "pass", "correctness": "PASS", "on_standard": "fail"},
            "risk_tier": "low", "reasons": ["r"], "what_changed": "w"}

    def test_extract_from_fence_and_prose(self):
        txt = "Sure!\n```json\n" + json.dumps(self.good) + "\n```\nbye"
        self.assertEqual(prompt.extract_json(txt)["risk_tier"], "low")

    def test_validate_normalises_and_rejects(self):
        self.assertEqual(prompt.validate_model_output(self.good)["checks"]["correctness"], "pass")
        bad = json.loads(json.dumps(self.good))
        bad["checks"]["safety"] = "maybe"
        with self.assertRaises(prompt.ModelOutputError):
            prompt.validate_model_output(bad)
        with self.assertRaises(prompt.ModelOutputError):
            prompt.extract_json("no json here")


class Providers(unittest.TestCase):
    def test_claude_refused(self):
        with self.assertRaises(providers.ConfigError):
            providers.resolve("copilot", "claude-haiku-4.5")

    def test_unknown_provider(self):
        with self.assertRaises(providers.ConfigError):
            providers.resolve("nope", None)

    def test_offline_needs_flag(self):
        with mock.patch.dict(os.environ, {"REVIEW_GATE_ALLOW_OFFLINE": ""}):
            with self.assertRaises(providers.ConfigError):
                providers.resolve("offline", None)

    def test_copilot_in_ci_needs_its_own_token(self):
        p, m = providers.resolve("copilot", None)
        env = {"GITHUB_ACTIONS": "true", "COPILOT_GITHUB_TOKEN": "", "GITHUB_TOKEN": "workflow-token"}
        with mock.patch.dict(os.environ, env), mock.patch.object(providers.shutil, "which", return_value="copilot"):
            with self.assertRaises(providers.ConfigError) as ctx:
                providers.call(p, m, "s", "u")
        self.assertIn("REPOSITORY secret", str(ctx.exception))

    @staticmethod
    def _events(answer, model, auto=False):
        lines = [{"type": "session.auto_mode_resolved", "data": {"chosenModel": model}}] if auto else []
        lines.append({"type": "assistant.message", "data": {"phase": "final_answer", "model": model,
                                                             "content": answer}})
        return "\n".join(json.dumps(x) for x in lines)

    def _run_copilot(self, auto_model, clear_cache=True):
        """Simulate Copilot Free: every named model refused, `auto` answers as auto_model."""
        if clear_cache:
            providers._COPILOT_REFUSED.clear()
        p, m = providers.resolve("copilot", None)
        calls = []
        self.last_cmds = []

        def fake_run(cmd, **kw):
            self.last_cmds.append(cmd)
            model = next(a.split("=", 1)[1] for a in cmd if a.startswith("--model="))
            calls.append(model)
            if model == "auto":
                return subprocess.CompletedProcess(cmd, 0, stdout=self._events('{"ok": 1}', auto_model, True),
                                                   stderr="")
            return subprocess.CompletedProcess(cmd, 1, stdout="",
                                               stderr=f'Error: Model "{model}" from --model flag is not available.')
        env = {"GITHUB_ACTIONS": "", "REVIEW_GATE_MODEL": ""}
        with mock.patch.dict(os.environ, env), mock.patch.object(providers.shutil, "which", return_value="copilot"), \
                mock.patch.object(providers.subprocess, "run", side_effect=fake_run):
            answer, meta = providers.call(p, m, "s", "u")
        return p, calls, answer, meta

    def test_copilot_free_plan_falls_back_to_auto_and_records_model(self):
        p, calls, answer, meta = self._run_copilot("gpt-6-luna")
        self.assertEqual(calls, [p.default_model, *p.fallback_models, "auto"])
        self.assertEqual(meta["model_used"], "gpt-6-luna")
        self.assertEqual(answer, '{"ok": 1}')

    def test_copilot_runs_lean_and_skips_refused_models_next_time(self):
        p, calls, _, _ = self._run_copilot("gpt-6-luna")
        for flag in ("--available-tools=view", "--disable-builtin-mcps", "--no-custom-instructions"):
            self.assertIn(flag, self.last_cmds[-1])
        _, calls2, _, meta = self._run_copilot("gpt-6-luna", clear_cache=False)
        self.assertEqual(calls2, ["auto"])          # refused models are not retried in this process
        self.assertEqual(meta["model_used"], "gpt-6-luna")
        providers._COPILOT_REFUSED.clear()

    def test_copilot_auto_choosing_claude_is_refused(self):
        with self.assertRaises(providers.ConfigError) as ctx:
            self._run_copilot("claude-haiku-4.5")
        self.assertIn("Claude", str(ctx.exception))

    def test_copilot_explicit_model_does_not_fall_back(self):
        p, _ = providers.resolve("copilot", None)
        fail = subprocess.CompletedProcess([], 1, stdout="", stderr='Model "gpt-x" is not available.')
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": ""}), \
                mock.patch.object(providers.shutil, "which", return_value="copilot"), \
                mock.patch.object(providers.subprocess, "run", return_value=fail) as run:
            with self.assertRaises(providers.ConfigError):
                providers.call(p, "gpt-x", "s", "u")
        self.assertEqual(run.call_count, 1)

    def test_missing_key_is_config_error(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            p, m = providers.resolve("openai", None)
            with self.assertRaises(providers.ConfigError):
                providers.call(p, m, "s", "u")


class Engine(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"REVIEW_GATE_ALLOW_OFFLINE": "1", "REVIEW_GATE_OFFLINE_REPLY": "",
                                                "REVIEW_GATE_FALLBACK": "off"})
        self.env.start()
        self.ctx = {"repo": "o/r", "event": "pull_request", "target_branch": "main",
                    "default_branch": "main", "via_pr": True, "visibility": "private-mine"}

    def tearDown(self):
        self.env.stop()

    def test_contract_shape(self):
        v = engine.review(D("README.md", ["hi"]), "", self.ctx, provider="offline")
        self.assertEqual(set(engine.VERDICT_KEYS) <= set(v), True)
        self.assertEqual(set(v["checks"]), set(engine.CHECK_KEYS))
        self.assertEqual(v["verdict"], "valid")
        self.assertIn("o/r", v["what_changed"])

    def test_secret_means_model_never_called(self):
        with mock.patch.object(providers, "call", side_effect=AssertionError("model was called")):
            v = engine.review(D("a.py", ['k = "AKIA' + 'Q7XW2M9KLP4ZT3RB"']), "", self.ctx, provider="offline")
        self.assertEqual(v["verdict"], "not-valid")
        self.assertEqual(v["checks"]["safety"], "fail")

    def test_fails_closed_on_garbage_reply(self):
        os.environ["REVIEW_GATE_OFFLINE_REPLY"] = "I think it looks fine!"
        v = engine.review(D("README.md", ["hi"]), "", self.ctx, provider="offline")
        self.assertEqual(v["verdict"], "not-valid")
        self.assertEqual(v["meta"]["status"], "unavailable")              # no verdict, fails closed
        self.assertTrue(any("no verdict" in r for r in v["reasons"]))

    def test_fails_closed_on_provider_error(self):
        with mock.patch.object(providers, "call", side_effect=providers.ProviderError("boom")):
            v = engine.review(D("README.md", ["hi"]), "", self.ctx, provider="offline")
        self.assertEqual(v["verdict"], "not-valid")

    def test_code_raises_risk_tier(self):
        v = engine.review(D("main.tf", ['resource "aws_iam_role" "r" {']), "", self.ctx, provider="offline")
        self.assertEqual(v["risk_tier"], "high")      # stub said low, code said high

    def test_declared_risk_floor(self):
        rules = "<!-- review-gate\nvisibility: private-mine\nrisk-floor: high\n-->"
        v = engine.review(D("README.md", ["hi"]), rules, dict(self.ctx, visibility=None), provider="offline")
        self.assertEqual(v["risk_tier"], "high")

    def test_empty_diff(self):
        self.assertEqual(engine.review("", "", self.ctx)["verdict"], "valid")

    def test_compare(self):
        gate_v = engine.review(D("README.md", ["hi"]), "", self.ctx, provider="offline")
        cmp = engine.compare({"verdict": "not-valid", "checks": {"safety": "fail"}}, gate_v)
        self.assertFalse(cmp["agree"])
        self.assertEqual(cmp["disagreements"], ["verdict", "checks.safety"])
        self.assertIn("DISAGREE", report.comparison_markdown(cmp))
        self.assertTrue(engine.compare({"verdict": "valid"}, gate_v)["agree"])

    def test_markdown(self):
        md = report.to_markdown(engine.review(D("README.md", ["hi"]), "", self.ctx, provider="offline"))
        self.assertIn(report.MARKER, md)
        self.assertIn("VALID", md)


class Git(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        run = lambda *a: subprocess.run(["git", "-C", self.repo, *a], check=True, capture_output=True)  # noqa: E731
        run("init", "-q", "-b", "main")
        run("config", "user.email", "t@example.com")
        run("config", "user.name", "t")
        Path(self.repo, "CLAUDE.md").write_text("<!-- review-gate\nvisibility: private-mine\n-->\n")
        Path(self.repo, "a.txt").write_text("one\n")
        run("add", ".")
        run("commit", "-q", "-m", "init")
        self.base = subprocess.run(["git", "-C", self.repo, "rev-parse", "HEAD"], capture_output=True,
                                   text=True).stdout.strip()
        self.run = run

    def tearDown(self):
        self.tmp.cleanup()

    def test_worktree_includes_untracked_and_images(self):
        Path(self.repo, "a.txt").write_text("two\n")
        Path(self.repo, "new.py").write_text("print('x')\n")
        Path(self.repo, "pic.png").write_bytes(evalsuite._png())
        diff = gitlocal.diff_worktree(self.repo, "main")
        paths = {f.path for f in diffutil.parse_diff(diff)}
        self.assertEqual(paths, {"a.txt", "new.py", "pic.png"})
        self.assertIn("pic.png", gitlocal.changed_images(self.repo, diff))
        self.assertIn("visibility: private-mine", gitlocal.read_rules(self.repo))

    def test_subprocesses_never_inherit_stdin(self):
        # Inside an MCP stdio server stdin is the protocol pipe; a git child touching it
        # hung a real review on Windows. Every subprocess must get DEVNULL.
        seen = []
        real = subprocess.run

        def spy(*a, **kw):
            seen.append(kw.get("stdin"))
            return real(*a, **kw)
        Path(self.repo, "new.py").write_text("print('x')\n")
        with mock.patch.object(gitlocal.subprocess, "run", side_effect=spy):
            gitlocal.diff_worktree(self.repo, "main")
        self.assertTrue(seen)
        self.assertTrue(all(s is subprocess.DEVNULL for s in seen))

    def test_unborn_repo_diffs_against_empty_tree(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "-C", d, "init", "-q", "-b", "main"], check=True)
            Path(d, "first.py").write_text("print(1)\n")
            paths = {f.path for f in diffutil.parse_diff(gitlocal.diff_worktree(d, "main"))}
            self.assertEqual(paths, {"first.py"})

    def test_ci_push_event(self):
        Path(self.repo, "a.txt").write_text("two\n")
        self.run("commit", "-qam", "change")
        head = subprocess.run(["git", "-C", self.repo, "rev-parse", "HEAD"], capture_output=True,
                              text=True).stdout.strip()
        ev = Path(self.repo, "event.json")
        ev.write_text(json.dumps({"before": self.base, "after": head,
                                  "head_commit": {"message": "change"},
                                  "repository": {"default_branch": "main"}}))
        env = {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": str(ev), "GITHUB_REPOSITORY": "o/r",
               "GITHUB_REF_NAME": "main", "GITHUB_TOKEN": ""}
        with mock.patch.dict(os.environ, env):
            e = ci.event_context(self.repo)
        self.assertEqual((e["base"], e["head"]), (self.base, head))
        self.assertFalse(e["context"]["via_pr"])                  # no token: conservative
        self.assertIn("a.txt", gitlocal.diff_range(self.repo, e["base"], e["head"]))

    def test_ci_pull_request_event(self):
        ev = Path(self.repo, "event.json")
        ev.write_text(json.dumps({"pull_request": {
            "number": 7, "title": "T", "body": "B",
            "base": {"sha": self.base, "ref": "main"}, "head": {"sha": self.base, "ref": "feat"}},
            "repository": {"default_branch": "main"}}))
        with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(ev),
                                          "GITHUB_REPOSITORY": "o/r"}):
            e = ci.event_context(self.repo)
        self.assertTrue(e["context"]["via_pr"])
        self.assertEqual(e["pr_number"], 7)
        self.assertEqual(e["rules_ref"], self.base)               # rules read at the BASE commit


VALID_REPLY = json.dumps({"checks": {"safety": "pass", "correctness": "pass", "on_standard": "pass"},
                          "risk_tier": "low", "reasons": ["ok"], "what_changed": "w"})
REJECT_REPLY = json.dumps({"checks": {"safety": "fail", "correctness": "pass", "on_standard": "pass"},
                           "risk_tier": "high", "reasons": ["unsafe"], "what_changed": "w"})


class Fallback(unittest.TestCase):
    """Fallback only to providers with keys, only when no verdict came back."""

    def setUp(self):
        self.env = mock.patch.dict(os.environ, {
            "REVIEW_GATE_ALLOW_OFFLINE": "1", "GITHUB_ACTIONS": "true", "REVIEW_GATE_MODEL": "auto",
            "OPENAI_API_KEY": "k", "GEMINI_API_KEY": "", "XAI_API_KEY": "", "DEEPSEEK_API_KEY": "",
            "COPILOT_GITHUB_TOKEN": "", "REVIEW_GATE_FALLBACK": ""})
        self.env.start()
        self.ctx = {"repo": "o/r", "event": "pull_request", "target_branch": "main",
                    "default_branch": "main", "via_pr": True, "visibility": "private-mine"}

    def tearDown(self):
        self.env.stop()

    def test_chain_only_adds_providers_with_keys(self):
        chain, skipped = providers.resolve_chain("copilot", None, "auto")
        self.assertEqual([p.name for p, _ in chain], ["copilot", "openai"])
        self.assertEqual(chain[0][1], "auto")                 # the model override is the primary's
        self.assertEqual(chain[1][1], providers.PROVIDERS["openai"].default_model)
        self.assertIn("gemini: no key", skipped)

    def test_chain_off_and_explicit_list(self):
        self.assertEqual(len(providers.resolve_chain("copilot", None, "off")[0]), 1)
        chain, _ = providers.resolve_chain("copilot,gemini,openai", None, "auto")
        self.assertEqual([p.name for p, _ in chain], ["copilot", "openai"])   # explicit order, keyless dropped

    def _review(self, replies):
        """replies: provider name -> reply text, or an Exception to raise."""
        calls = []

        def fake_call(p, m, system, user, images=None):
            calls.append(p.name)
            r = replies[p.name]
            if isinstance(r, Exception):
                raise r
            return r, {"usage": None}
        with mock.patch.object(providers, "call", side_effect=fake_call):
            v = engine.review(D("README.md", ["hi"]), "", self.ctx, provider="offline,openai", fallback="auto")
        return v, calls

    def test_falls_back_when_no_verdict(self):
        v, calls = self._review({"offline": providers.ProviderError("allowance used up"), "openai": VALID_REPLY})
        self.assertEqual(calls, ["offline", "openai"])
        self.assertEqual((v["verdict"], v["meta"]["status"], v["meta"]["provider"]), ("valid", "reviewed", "openai"))
        self.assertIn("allowance used up", v["meta"]["fallback_reason"])

    def test_never_falls_back_after_a_verdict(self):
        v, calls = self._review({"offline": REJECT_REPLY, "openai": VALID_REPLY})
        self.assertEqual(calls, ["offline"])                    # no reviewer shopping
        self.assertEqual((v["verdict"], v["meta"]["status"]), ("not-valid", "reviewed"))

    def test_garbage_reply_counts_as_no_verdict(self):
        v, calls = self._review({"offline": "looks fine to me", "openai": VALID_REPLY})
        self.assertEqual(calls, ["offline", "openai"])
        self.assertEqual(v["verdict"], "valid")

    def test_all_fail_is_unavailable_not_rejected(self):
        v, _ = self._review({"offline": providers.ProviderError("quota"), "openai": providers.ProviderError("429")})
        self.assertEqual((v["verdict"], v["meta"]["status"]), ("not-valid", "unavailable"))
        self.assertEqual(len(v["meta"]["attempts"]), 2)

    def test_a_missing_or_refused_key_is_error_not_unavailable(self):
        v, _ = self._review({"offline": providers.ProviderError("quota"),
                             "openai": providers.ConfigError("provider refused the API key (401)")})
        self.assertEqual(v["meta"]["status"], "error")             # never bypassable

    def test_single_provider_says_no_fallback_configured(self):
        os.environ["OPENAI_API_KEY"] = ""
        with mock.patch.object(providers, "call", side_effect=providers.ProviderError("allowance used up")):
            v = engine.review(D("README.md", ["hi"]), "", self.ctx, provider="offline", fallback="auto")
        self.assertEqual(v["meta"]["status"], "unavailable")
        self.assertTrue(any("No fallback reviewer" in r for r in v["reasons"]))

    def test_misconfigured_gate_is_error(self):
        v = engine.review(D("README.md", ["hi"]), "", self.ctx, provider="nope")
        self.assertEqual(v["meta"]["status"], "error")

    def test_typo_in_explicit_chain_is_error_not_unavailable(self):
        v = engine.review(D("README.md", ["hi"]), "", self.ctx, provider="offline,opneai", fallback="auto")
        self.assertEqual(v["meta"]["status"], "error")         # never bypassable


class Bypass(unittest.TestCase):
    """The owner may bypass ONLY a missing reviewer, never a verdict or a code check."""

    label_time = "2026-10-21T12:00:00Z"          # after the run was triggered (11:00)

    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r",
                                                "GITHUB_REPOSITORY_OWNER": "owner", "GITHUB_ACTOR": "owner"})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    @staticmethod
    def _verdict(status="unavailable", branch="pass"):
        return {"verdict": "not-valid", "reasons": [], "meta": {"status": status},
                "checks": {"safety": "fail", "correctness": "fail", "on_standard": "fail", "branch_rule": branch}}

    def _api(self, labeler, labels=("review-gate-bypass",)):
        def fake(method, path, token, body=None):
            if path.endswith("/labels"):
                return [{"name": n} for n in labels]
            if "/events" in path:
                return [{"event": "labeled", "label": {"name": "review-gate-bypass"}, "actor": {"login": labeler},
                         "created_at": self.label_time}]
            return []
        return fake

    def test_owner_label_bypasses_unavailable(self):
        v = self._verdict()
        with mock.patch.object(ci, "_api", side_effect=self._api("owner")):
            ci.apply_bypass(v, {"pr_number": 3, "context": {}, "triggered_at": "2026-10-21T11:00:00Z"}, allow=True)
        self.assertEqual(v["meta"]["status"], "bypassed")

    def test_label_from_before_the_run_does_not_count(self):
        self.label_time = "2026-10-21T10:00:00Z"   # pre-emptive or leftover label
        v = self._verdict()
        with mock.patch.object(ci, "_api", side_effect=self._api("owner")):
            ci.apply_bypass(v, {"pr_number": 3, "context": {}, "triggered_at": "2026-10-21T11:00:00Z"}, allow=True)
        self.assertEqual(v["meta"]["status"], "unavailable")
        self.assertIn("before this run", v["meta"]["bypass_not_applied"])

    def test_label_by_someone_else_does_not(self):
        v = self._verdict()
        with mock.patch.object(ci, "_api", side_effect=self._api("intruder")):
            ci.apply_bypass(v, {"pr_number": 3, "context": {}, "triggered_at": "2026-10-21T11:00:00Z"}, allow=True)
        self.assertEqual(v["meta"]["status"], "unavailable")
        self.assertIn("not the owner", v["meta"]["bypass_not_applied"])

    def test_not_allowed_unless_repo_opts_in(self):
        v = self._verdict()
        with mock.patch.object(ci, "_api", side_effect=self._api("owner")):
            ci.apply_bypass(v, {"pr_number": 3, "context": {}, "triggered_at": "2026-10-21T11:00:00Z"}, allow=False)
        self.assertEqual(v["meta"]["status"], "unavailable")

    def test_latest_label_event_wins_across_pages(self):
        # Owner labeled long ago (page 1); someone else re-added it later (page 2).
        page1 = [{"event": "labeled", "label": {"name": "review-gate-bypass"}, "actor": {"login": "owner"}}]
        page1 += [{"event": "commented"}] * 99
        page2 = [{"event": "labeled", "label": {"name": "review-gate-bypass"}, "actor": {"login": "intruder"}}]

        def fake(method, path, token, body=None):
            if path.endswith("/labels"):
                return [{"name": "review-gate-bypass"}]
            return page2 if "page=2" in path else page1 if "page=1" in path else []
        v = self._verdict()
        with mock.patch.object(ci, "_api", side_effect=fake):
            ci.apply_bypass(v, {"pr_number": 3, "context": {}, "triggered_at": "2026-10-21T11:00:00Z"}, allow=True)
        self.assertEqual(v["meta"]["status"], "unavailable")
        self.assertIn("intruder", v["meta"]["bypass_not_applied"])

    def test_too_many_events_fails_closed(self):
        full = [{"event": "commented"}] * 100

        def fake(method, path, token, body=None):
            return [{"name": "review-gate-bypass"}] if path.endswith("/labels") else full
        v = self._verdict()
        with mock.patch.object(ci, "_api", side_effect=fake):
            ci.apply_bypass(v, {"pr_number": 3, "context": {}, "triggered_at": "2026-10-21T11:00:00Z"}, allow=True)
        self.assertEqual(v["meta"]["status"], "unavailable")
        self.assertIn("too many events", v["meta"]["bypass_not_applied"])

    def test_never_bypasses_a_real_verdict(self):
        v = self._verdict(status="reviewed")
        with mock.patch.object(ci, "_api", side_effect=self._api("owner")):
            ci.apply_bypass(v, {"pr_number": 3, "context": {}, "triggered_at": "2026-10-21T11:00:00Z"}, allow=True)
        self.assertEqual(v["meta"]["status"], "reviewed")

    def test_never_bypasses_a_failed_branch_rule(self):
        v = self._verdict(branch="fail")
        with mock.patch.object(ci, "_api", side_effect=self._api("owner")):
            ci.apply_bypass(v, {"pr_number": 3, "context": {}, "triggered_at": "2026-10-21T11:00:00Z"}, allow=True)
        self.assertEqual(v["meta"]["status"], "unavailable")
        self.assertIn("branch rule", v["meta"]["bypass_refused"])

    def test_push_bypass_uses_the_merged_prs_label(self):
        def fake(method, path, token, body=None):
            if "/pulls" in path:
                return [{"number": 9, "merged_at": "2026-10-21", "base": {"ref": "main"}}]
            return self._api("owner")(method, path, token, body)
        v = self._verdict()
        ev = {"pr_number": None, "head": "abc", "context": {"target_branch": "main"}, "triggered_at": "2026-10-21T11:00:00Z"}
        with mock.patch.object(ci, "_api", side_effect=fake):
            ci.apply_bypass(v, ev, allow=True)
        self.assertEqual(v["meta"]["status"], "bypassed")
        self.assertIn("#9", v["meta"]["bypass"])

    def test_direct_push_can_never_be_bypassed(self):
        v = self._verdict()
        ev = {"pr_number": None, "head": "abc", "context": {"target_branch": "main"}, "triggered_at": "2026-10-21T11:00:00Z"}
        with mock.patch.object(ci, "_api", side_effect=lambda *a, **k: []):
            ci.apply_bypass(v, ev, allow=True)
        self.assertEqual(v["meta"]["status"], "unavailable")
        self.assertIn("direct push", v["meta"]["bypass_not_applied"])


class OfflineSuite(unittest.TestCase):
    def test_code_decided_cases_all_correct(self):
        out = evalsuite.run(offline=True)
        bad = [r for r in out["results"] if r["kind"] == "bad"]
        good = [r for r in out["results"] if r["kind"] == "good"]
        self.assertTrue(bad and good)
        self.assertEqual([r["name"] for r in bad if r["outcome"] != "caught"], [])
        self.assertEqual([r["name"] for r in good if r["outcome"] != "passed"], [])


if __name__ == "__main__":
    unittest.main()
