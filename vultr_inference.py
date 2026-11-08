"""
vultr_inference.py — the ONLY LLM path in HashBound.

OpenAI-compatible client for Vultr Serverless Inference.

Configuration (environment only — never in code, never in the repo):
    VULTR_INFERENCE_BASE_URL   default https://api.vultrinference.com/v1
    VULTR_INFERENCE_API_KEY    the Serverless Inference key (separate
                               from the Vultr account API key)
    VULTR_INFERENCE_MODEL      model id pinned from GET /v1/models at
                               deploy time; code a flash-tier fallback
                               rather than assuming an id survives.

Behaviour without a key: the client reports not-configured and every
caller fails closed — the deterministic policy layer still answers
ALLOW/DENY/GATE on its own, and grey-zone work queues for a human.
That is deliberate: DENY-class verdicts never depend on a model.

Transport is injectable for tests (no network in the test suite).
Stdlib only (urllib).
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Callable, Optional

DEFAULT_BASE_URL = "https://api.vultrinference.com/v1"
# Flash-tier fallback candidates named in the Nov 7 research; the
# deployed model is pinned from the live catalog, this is only the
# last-resort default when no env pin exists.
DEFAULT_MODEL = "deepseek-v4.1-flash-1017"


def _default_transport(url: str, headers: dict, body: bytes,
                       timeout: float) -> dict:
    req = urllib.request.Request(url, data=body, headers=headers,
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class VultrInferenceClient:
    def __init__(self, base_url: Optional[str] = None,
                 api_key: Optional[str] = None,
                 model: Optional[str] = None,
                 transport: Optional[Callable] = None,
                 timeout: float = 30.0):
        self.base_url = (base_url
                         or os.environ.get("VULTR_INFERENCE_BASE_URL")
                         or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = (api_key
                        if api_key is not None
                        else os.environ.get("VULTR_INFERENCE_API_KEY", ""))
        self.model = (model
                      or os.environ.get("VULTR_INFERENCE_MODEL")
                      or DEFAULT_MODEL)
        self._transport = transport or _default_transport
        self.timeout = timeout

    # -- state ---------------------------------------------------------------

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def status(self) -> dict:
        return {"configured": self.is_configured(),
                "base_url": self.base_url,
                "model": self.model}

    # -- core call -------------------------------------------------------------

    def chat_completion(self, messages: list, max_tokens: int = 512,
                        temperature: float = 0.0) -> Optional[str]:
        """Return the assistant text, or None on ANY failure.

        None means 'no model answer' — callers must fail closed, never
        treat None as approval.
        """
        if not self.is_configured():
            return None
        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode("utf-8")
        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json"}
        try:
            data = self._transport(f"{self.base_url}/chat/completions",
                                   headers, body, self.timeout)
        except Exception:
            return None
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return None

    # -- the two roles the gate/app actually use -------------------------------

    def screen_tool_call(self, tool: str, args: dict) -> Optional[bool]:
        """Classifier screen: True only on a confident 'safe' JSON answer.

        Returns None when unconfigured / unreachable / unparseable —
        the gate treats None as 'not cleared' and queues. Fail closed.
        """
        text = self.chat_completion([
            {"role": "system",
             "content": ("You are a safety screen for an agent approval "
                         "gate. Answer with JSON only: "
                         "{\"safe\": true|false, \"confidence\": 0.0-1.0}. "
                         "Safe means read-only or trivially reversible.")},
            {"role": "user",
             "content": f"tool={tool} args={json.dumps(args, default=str)}"},
        ], max_tokens=80)
        if not text:
            return None
        try:
            start, end = text.find("{"), text.rfind("}")
            parsed = json.loads(text[start:end + 1])
            if parsed.get("safe") is True and \
                    float(parsed.get("confidence", 0)) >= 0.8:
                return True
            return False
        except Exception:
            return None

    def prepare_field_values(self, instruction: str,
                             fields: list) -> Optional[dict]:
        """Form-filler role: the model PREPARES values; it never submits.

        The prepared payload still goes through the hash-bound gate —
        a human approves the exact values (hash-bound) before any
        submit can execute. Returns None when unconfigured.
        """
        text = self.chat_completion([
            {"role": "system",
             "content": ("You prepare form field values. Answer with a "
                         "JSON object mapping each field name to its "
                         "value, and nothing else.")},
            {"role": "user",
             "content": (f"Instruction: {instruction}\n"
                         f"Fields: {json.dumps(fields)}")},
        ], max_tokens=400)
        if not text:
            return None
        try:
            start, end = text.find("{"), text.rfind("}")
            return json.loads(text[start:end + 1])
        except Exception:
            return None


def make_screen(client: VultrInferenceClient) -> Callable:
    """Adapt the client to HashBoundGate's screen callable.

    Only a confident True clears; None/False/exception all queue.
    """
    def _screen(call) -> bool:
        verdict = client.screen_tool_call(call.tool, call.args)
        return verdict is True
    return _screen
