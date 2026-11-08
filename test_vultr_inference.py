"""
test_vultr_inference.py — the inference client fails CLOSED.

No network: transport is injected. Run: python3 -m unittest
test_vultr_inference -v
"""

import json
import os
import unittest
from unittest import mock

from vultr_inference import VultrInferenceClient, make_screen
from decision_layer import ToolCall


def fake_transport(payload):
    def _t(url, headers, body, timeout):
        _t.last_url = url
        _t.last_headers = headers
        _t.last_body = json.loads(body.decode())
        return payload
    return _t


def chat_payload(content):
    return {"choices": [{"message": {"content": content}}]}


class ConfigTests(unittest.TestCase):

    def test_unconfigured_without_key(self):
        c = VultrInferenceClient(api_key="", transport=fake_transport({}))
        self.assertFalse(c.is_configured())
        self.assertIsNone(c.chat_completion([{"role": "user",
                                              "content": "hi"}]))
        self.assertIsNone(c.screen_tool_call("read_file", {}))
        self.assertIsNone(c.prepare_field_values("x", ["a"]))

    def test_env_vars_are_read(self):
        env = {"VULTR_INFERENCE_BASE_URL": "https://example.test/v1/",
               "VULTR_INFERENCE_API_KEY": "test-key-not-real",
               "VULTR_INFERENCE_MODEL": "some-model-1"}
        with mock.patch.dict(os.environ, env, clear=False):
            c = VultrInferenceClient()
        self.assertTrue(c.is_configured())
        self.assertEqual(c.base_url, "https://example.test/v1")
        self.assertEqual(c.model, "some-model-1")
        # the key itself is never part of the public status dict
        self.assertNotIn("test-key-not-real", json.dumps(c.status()))


class ScreenTests(unittest.TestCase):

    def test_confident_safe_clears(self):
        t = fake_transport(chat_payload('{"safe": true, "confidence": 0.95}'))
        c = VultrInferenceClient(api_key="k", transport=t)
        self.assertTrue(c.screen_tool_call("fetch_url",
                                           {"url": "https://x.test"}))
        self.assertTrue(t.last_url.endswith("/chat/completions"))
        self.assertEqual(t.last_headers["Authorization"], "Bearer k")

    def test_unsafe_or_unconfident_does_not_clear(self):
        for content in ('{"safe": false, "confidence": 0.99}',
                        '{"safe": true, "confidence": 0.3}',
                        'not json at all'):
            c = VultrInferenceClient(
                api_key="k", transport=fake_transport(chat_payload(content)))
            self.assertIsNot(c.screen_tool_call("x", {}), True, content)

    def test_transport_failure_fails_closed(self):
        def boom(url, headers, body, timeout):
            raise RuntimeError("network down")
        c = VultrInferenceClient(api_key="k", transport=boom)
        self.assertIsNone(c.chat_completion([{"role": "user",
                                              "content": "hi"}]))
        self.assertIsNone(c.screen_tool_call("x", {}))

    def test_make_screen_adapter(self):
        c = VultrInferenceClient(api_key="", transport=fake_transport({}))
        screen = make_screen(c)
        self.assertFalse(screen(ToolCall(tool="anything", args={})))


class FieldPrepTests(unittest.TestCase):

    def test_prepare_field_values_parses_json(self):
        t = fake_transport(chat_payload('{"name": "Ada", "qty": 2}'))
        c = VultrInferenceClient(api_key="k", transport=t)
        out = c.prepare_field_values("order two", ["name", "qty"])
        self.assertEqual(out, {"name": "Ada", "qty": 2})


if __name__ == "__main__":
    unittest.main()
