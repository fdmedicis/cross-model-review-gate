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

    def test_copilot_falls_back_when_model_not_on_plan(self):
        p, m = providers.resolve("copilot", None)
        calls = []

        def fake_run(cmd, **kw):
            model = next(a.split("=", 1)[1] for a in cmd if a.startswith("--model="))
            calls.append(model)
            ok = model == p.fallback_models[1]
            return subprocess.CompletedProcess(cmd, 0 if ok else 1, stdout='{"x": 1}' if ok else "",
                                               stderr="" if ok else f'Error: Model "{model}" is not available.')
        env = {"GITHUB_ACTIONS": "", "REVIEW_GATE_MODEL": ""}
        with mock.patch.dict(os.environ, env), mock.patch.object(providers.shutil, "which", return_value="copilot"), \
                mock.patch.object(providers.subprocess, "run", side_effect=fake_run):
            _, meta = providers.call(p, m, "s", "u")
        self.assertEqual(calls, [p.default_model, *p.fallback_models[:2]])
        self.assertEqual(meta["model_used"], p.fallback_models[1])
        self.assertFalse(any("claude" in c for c in calls))

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
        self.env = mock.patch.dict(os.environ, {"REVIEW_GATE_ALLOW_OFFLINE": "1", "REVIEW_GATE_OFFLINE_REPLY": ""})
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
        self.assertTrue(any("gate error" in r for r in v["reasons"]))

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
