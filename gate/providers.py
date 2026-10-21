"""Review providers: who plays the second model.

Four providers speak the OpenAI-compatible chat-completions API, so one HTTP
client covers them; switching provider is configuration, not code. Copilot has
no public chat API for this, so it runs through the official Copilot CLI.

Rules every provider follows:
- The API key or token comes from an environment variable, never from code.
- A Claude model is refused. The point of the gate is a second opinion from a
  different model family; Claude reviewing Claude is an echo.
- Any failure raises ProviderError, and the engine turns that into NOT-VALID.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .prompt import MODEL_SCHEMA


class ProviderError(RuntimeError):
    """The provider could not produce a reply. The gate fails closed."""


class ConfigError(ProviderError):
    """The gate is misconfigured (unknown provider, missing key, Claude model...)."""


@dataclass(frozen=True)
class Provider:
    name: str
    kind: str                 # "http" | "copilot" | "offline"
    key_env: str
    default_model: str
    json_mode: str = "none"   # first response_format to try: json_schema | json_object | none
    vision: bool = False      # can it look at changed images?
    base_url: str = ""
    # Tried in order when the default model is not on the account's plan. Only used
    # when no model was set explicitly. Never contains a Claude model.
    fallback_models: tuple = ()


# Default models were current on the providers' pages in October 2026. Model names
# change often: override with REVIEW_GATE_MODEL / the `model` input when they do.
PROVIDERS: dict[str, Provider] = {
    "openai": Provider("openai", "http", "OPENAI_API_KEY", "gpt-6-sol",
                       json_mode="json_schema", vision=True, base_url="https://api.openai.com/v1"),
    "gemini": Provider("gemini", "http", "GEMINI_API_KEY", "gemini-3.8-flash",
                       json_mode="json_object", vision=True,
                       base_url="https://generativelanguage.googleapis.com/v1beta/openai"),
    "deepseek": Provider("deepseek", "http", "DEEPSEEK_API_KEY", "deepseek-v4-flash",
                         json_mode="json_object", vision=False, base_url="https://api.deepseek.com"),
    "grok": Provider("grok", "http", "XAI_API_KEY", "grok-4.6",
                     json_mode="json_schema", vision=True, base_url="https://api.x.ai/v1"),
    # Which models a Copilot account may name depends on its plan. The gate tries these,
    # then Copilot's automatic choice (the only option on Copilot Free), and accepts an
    # automatic choice only when the CLI's events show it was not a Claude model.
    "copilot": Provider("copilot", "copilot", "COPILOT_GITHUB_TOKEN", "gpt-6-sol",
                        json_mode="none", vision=True,
                        fallback_models=("gpt-5.4",)),
    # Test double. Refuses to run unless REVIEW_GATE_ALLOW_OFFLINE=1, so it can never
    # silently stand in for a real reviewer in CI.
    "offline": Provider("offline", "offline", "", "offline-stub", vision=True),
}

DEFAULT_PROVIDER = "openai"

_MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
         ".gif": "image/gif", ".webp": "image/webp"}


def resolve(provider: str | None, model: str | None, use_env_model: bool = True) -> tuple[Provider, str]:
    name = (provider or os.environ.get("REVIEW_GATE_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    name = name.split(",")[0].strip()          # a chain "a,b" resolves to its first provider here
    if name not in PROVIDERS:
        raise ConfigError(f"unknown provider '{name}'. Use one of: "
                          + ", ".join(k for k in PROVIDERS if k != "offline"))
    p = PROVIDERS[name]
    env_model = os.environ.get("REVIEW_GATE_MODEL") if use_env_model else None
    m = (model or env_model or p.default_model).strip()
    if "claude" in m.lower() or "anthropic" in m.lower():
        raise ConfigError(f"model '{m}' is a Claude model. The gate reviews Claude's work, "
                          f"so the reviewer must be a different model family.")
    if p.kind == "offline" and os.environ.get("REVIEW_GATE_ALLOW_OFFLINE") != "1":
        raise ConfigError("the offline stub only runs in tests (REVIEW_GATE_ALLOW_OFFLINE=1)")
    return p, m


# --- Fallback chain ------------------------------------------------------------------
# If the first provider cannot produce a verdict (allowance used up, rate limit, outage,
# missing credentials), the next provider THAT HAS CREDENTIALS reviews instead. A
# provider without a key is skipped silently: no key, no fallback. A verdict is never
# re-asked elsewhere, valid or not: the engine stops at the first verdict it gets.

FALLBACK_ORDER = ("copilot", "openai", "gemini", "grok", "deepseek")


def has_credentials(p: Provider) -> bool:
    if p.kind == "offline":
        return os.environ.get("REVIEW_GATE_ALLOW_OFFLINE") == "1"
    # Only an actual key counts. (An installed Copilot CLI proves nothing about a login;
    # Copilot as the FIRST provider is always tried, which covers a local CLI login.)
    return bool(os.environ.get(p.key_env, "").strip())


def resolve_chain(provider: str | None, model: str | None,
                  fallback: str | None = None) -> tuple[list, list]:
    """Return ([(Provider, model), ...], [skipped notes]).

    provider: one name, or an explicit ordered list "copilot,openai".
    fallback: "auto" (default) adds, after a single provider, every other provider
              that has credentials, in FALLBACK_ORDER; "off" uses only the first.
    The model override applies to the FIRST provider only; fallbacks use their default.
    Raises ConfigError if the first provider is unknown or a Claude model is requested.
    """
    spec = (provider or os.environ.get("REVIEW_GATE_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    names = [n.strip() for n in spec.split(",") if n.strip()] or [DEFAULT_PROVIDER]
    mode = (fallback or os.environ.get("REVIEW_GATE_FALLBACK") or "auto").strip().lower()
    if mode == "off":
        names = names[:1]
    elif mode == "auto" and len(names) == 1:
        names += [n for n in FALLBACK_ORDER if n not in names]
    names = list(dict.fromkeys(names))

    chain, skipped = [resolve(names[0], model)], []
    for name in names[1:]:
        p = PROVIDERS.get(name)
        if p is None or (p.kind == "offline" and os.environ.get("REVIEW_GATE_ALLOW_OFFLINE") != "1"):
            # A typo must not look like "no reviewer available" (which a repo may bypass).
            raise ConfigError(f"unknown provider '{name}' in the provider list")
        elif not has_credentials(p):
            skipped.append(f"{name}: no key")
        else:
            chain.append(resolve(name, None, use_env_model=False))
    return chain, skipped


def call(p: Provider, model: str, system: str, user: str,
         images: list[tuple[str, bytes]] | None = None, timeout: int = 180) -> tuple[str, dict]:
    """Send one review request. Returns (raw reply text, usage/meta dict)."""
    images = images or []
    if images and not p.vision:
        raise ConfigError(f"{len(images)} changed image(s), but provider '{p.name}' cannot look at "
                          f"images. Use a vision-capable provider for changes that touch images.")
    if p.kind == "http":
        return _http_call(p, model, system, user, images, timeout)
    if p.kind == "copilot":
        return _copilot_call(p, model, system, user, images, timeout)
    if p.kind == "offline":
        reply = os.environ.get("REVIEW_GATE_OFFLINE_REPLY") or json.dumps({
            "checks": {"safety": "pass", "correctness": "pass", "on_standard": "pass"},
            "risk_tier": "low", "reasons": ["offline stub: no model was called"],
            "what_changed": "offline stub"})
        return reply, {"usage": None}
    raise ConfigError(f"provider kind '{p.kind}' is not implemented")


# --- OpenAI-compatible HTTP -----------------------------------------------------------

_MODES = ("json_schema", "json_object", "none")


def _http_call(p, model, system, user, images, timeout):
    key = os.environ.get(p.key_env, "").strip()
    if not key:
        raise ConfigError(f"{p.key_env} is not set (provider '{p.name}')")
    if images:
        content = [{"type": "text", "text": user}]
        for path, data in images:
            ext = "." + path.rsplit(".", 1)[-1].lower()
            b64 = base64.b64encode(data).decode("ascii")
            content.append({"type": "image_url",
                            "image_url": {"url": f"data:{_MIME.get(ext, 'image/png')};base64,{b64}"}})
    else:
        content = user
    body = {"model": model, "messages": [{"role": "system", "content": system},
                                         {"role": "user", "content": content}]}
    url = p.base_url.rstrip("/") + "/chat/completions"

    last_err = None
    for mode in _MODES[_MODES.index(p.json_mode):]:
        req = dict(body)
        if mode == "json_schema":
            req["response_format"] = {"type": "json_schema", "json_schema": {
                "name": "review_verdict", "strict": True, "schema": MODEL_SCHEMA}}
        elif mode == "json_object":
            req["response_format"] = {"type": "json_object"}
        try:
            data = _post_json(url, req, key, timeout)
        except _BadRequest as e:
            # Some models reject a response_format they don't support. Fall back to
            # a looser one; the reply is validated strictly either way.
            if "response_format" in e.body or "json" in e.body.lower() or "schema" in e.body.lower():
                last_err = e
                continue
            raise ProviderError(f"{p.name} rejected the request (400): {e.body[:300]}") from e
        text = _message_text(data)
        return text, {"usage": data.get("usage"), "response_format": mode}
    raise ProviderError(f"{p.name} rejected every response format: {last_err.body[:300] if last_err else ''}")


class _BadRequest(Exception):
    def __init__(self, body):
        super().__init__(body)
        self.body = body


def _post_json(url, payload, key, timeout, attempts=3):
    raw = json.dumps(payload).encode("utf-8")
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(url, data=raw, method="POST", headers={
            "Authorization": f"Bearer {key}", "Content-Type": "application/json",
            "User-Agent": "cross-model-review-gate"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            if e.code == 400:
                raise _BadRequest(body) from e
            if e.code in (429, 500, 502, 503, 504) and attempt < attempts:
                time.sleep(2 ** attempt)
                continue
            if e.code in (401, 403):
                raise ConfigError(f"provider refused the API key ({e.code}): {body[:200]}") from e
            raise ProviderError(f"provider HTTP {e.code}: {body[:300]}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < attempts:
                time.sleep(2 ** attempt)
                continue
            raise ProviderError(f"could not reach the provider: {e}") from e
    raise ProviderError("provider retries exhausted")


def _message_text(data: dict) -> str:
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise ProviderError(f"unexpected provider response shape: {str(data)[:300]}") from e
    if isinstance(content, list):  # some providers return content parts
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    return content or ""


# --- GitHub Copilot CLI -------------------------------------------------------------------

_COPILOT_INSTRUCTION = (
    "Read the file review_request.md in the current directory. It contains your instructions "
    "and the change to review. Follow those instructions exactly and reply with ONLY the JSON "
    "object they ask for. Do not modify any file and do not run any command."
)


# The reviewer reads one request file and answers. It gets only the file viewer:
# no GitHub MCP server (no repo access through the token), no shell, no writes, and
# no custom instructions picked up from the working directory. Fewer tools also
# halves the CLI's start-up and prompt size (about 25 s -> 12 s for a trivial call).
_COPILOT_LEAN_FLAGS = ("--allow-tool=read", "--available-tools=view",
                       "--disable-builtin-mcps", "--no-custom-instructions")

_COPILOT_REFUSED: set = set()


def _is_claude(model_id: str) -> bool:
    return "claude" in (model_id or "").lower() or "anthropic" in (model_id or "").lower()


def _parse_copilot_events(stdout: str) -> tuple[str, str]:
    """From `--output-format=json` (one JSON event per line) return (final answer, model).

    The model comes from the CLI's own events, so the gate can verify WHO reviewed
    even when Copilot chose the model automatically."""
    answer, model, deltas = "", "", []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        data = ev.get("data") or {}
        kind = ev.get("type")
        if kind == "session.auto_mode_resolved" and data.get("chosenModel"):
            model = model or str(data["chosenModel"])
        elif kind == "assistant.message_delta":
            deltas.append(str(data.get("deltaContent") or ""))
        elif kind == "assistant.message" and data.get("phase", "final_answer") == "final_answer":
            answer = str(data.get("content") or "")
            model = str(data.get("model") or model)
        elif kind == "model.call_final_result" and data.get("model"):
            model = str(data["model"])
    return (answer or "".join(deltas)), model


def _copilot_call(p, model, system, user, images, timeout):
    exe = shutil.which("copilot")
    if not exe:
        raise ConfigError("the Copilot CLI is not installed (npm install -g @github/copilot)")
    # In CI the only usable credential is the PAT. Without it the CLI would fall back to
    # the workflow's GITHUB_TOKEN, which cannot use a personal Copilot plan, and fail
    # with a confusing policy error. Locally the CLI may use its own stored login.
    if os.environ.get("GITHUB_ACTIONS") == "true" and not os.environ.get(p.key_env, "").strip():
        raise ConfigError(f"{p.key_env} is empty in this run. Add it as a REPOSITORY secret under "
                          f"Settings > Secrets and variables > Actions (not an environment secret), "
                          f"and pass it to the gate in the caller workflow.")

    # Which models a plan may name differs: Copilot Free accepts only automatic choice.
    # Without an explicit model: try the preferred models, then `auto`. `auto` is
    # accepted only if the CLI's events show a non-Claude model answered.
    explicit = bool(os.environ.get("REVIEW_GATE_MODEL")) or model != p.default_model
    candidates = [model] if explicit else [model, *p.fallback_models, "auto"]
    candidates = [m for m in dict.fromkeys(candidates) if not _is_claude(m)]
    # Skip models this process already saw refused (a long-lived MCP server reviews
    # many times; each refusal costs a CLI start-up). Never skip an explicit model.
    if not explicit:
        candidates = [m for m in candidates if m not in _COPILOT_REFUSED] or candidates

    # The CLI sees only what it needs: no other provider's key, and not the
    # workflow's GITHUB_TOKEN (which it would otherwise fall back to).
    hidden = {q.key_env for q in PROVIDERS.values() if q.key_env and q.key_env != p.key_env}
    hidden.add("GITHUB_TOKEN")
    if os.environ.get(p.key_env):
        hidden.add("GH_TOKEN")
    env = {k: v for k, v in os.environ.items() if k not in hidden}

    unavailable = []
    with tempfile.TemporaryDirectory(prefix="review-gate-") as d:
        # The request goes in a file: a 40k-token diff is far beyond the
        # single-argument limit of a command line.
        with open(os.path.join(d, "review_request.md"), "w", encoding="utf-8") as fh:
            fh.write(system + "\n\n---\n\n" + user)
        attachments = []
        for i, (path, data) in enumerate(images):
            img = os.path.join(d, f"image_{i}_{os.path.basename(path)}")
            with open(img, "wb") as fh:
                fh.write(data)
            attachments.append(f"--attachment={img}")

        for m in candidates:
            cmd = [exe, "-p", _COPILOT_INSTRUCTION, "--no-ask-user", "--output-format=json",
                   f"--model={m}", *_COPILOT_LEAN_FLAGS, *attachments]
            try:
                # stdin=DEVNULL: the CLI reads piped stdin as extra prompt, and inside an
                # MCP stdio server the inherited stdin is the protocol pipe.
                r = subprocess.run(cmd, cwd=d, capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=timeout, env=env,
                                   stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired as e:
                raise ProviderError(f"Copilot CLI timed out after {timeout}s (model {m})") from e
            out = (r.stderr or "") + (r.stdout or "")
            if r.returncode != 0:
                if "not available" in out.lower() and m != "auto":
                    unavailable.append(m)       # not on this plan: try the next one
                    _COPILOT_REFUSED.add(m)
                    continue
                raise ProviderError(f"Copilot CLI exited with {r.returncode} (model {m}): {out.strip()[-900:]}")
            answer, used = _parse_copilot_events(r.stdout)
            used = used or (m if m != "auto" else "")
            if not used:
                raise ProviderError("Copilot answered, but its output did not say which model reviewed; "
                                    "the gate cannot confirm it was not Claude")
            if _is_claude(used):
                raise ConfigError(f"Copilot's automatic choice was {used}, a Claude model. The reviewer must "
                                  f"be a different model family: set the `model` input to a non-Claude model.")
            return answer, {"usage": None, "model_used": used, "requested_model": m,
                            "models_unavailable": unavailable}
    raise ConfigError("no usable Copilot model: " + ", ".join(unavailable) + " were not available. "
                      "Set the `model` input to one your plan includes (not a Claude model).")
