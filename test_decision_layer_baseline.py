"""
Tests for decision_layer.py — run: python3 -m unittest -v
Covers the four contract cases:
  1. confident cheap decision is NOT escalated
  2. low-confidence decision IS escalated to the strong decider
  3. policy-denied tool call is blocked (never queued, never allowed)
  4. grey-zone tool call is queued for human approval, not executed/allowed
Plus supporting cases for the screen-pass path, the allow-list path, and
escalation with no strong tier configured.
"""

import unittest

from decision_layer import (
    Bool, Choice, DecisionRequest, Router, RulesDecider,
    CallableStrongDecider, ToolCall, ToolGate,
)


class SpyStrong(CallableStrongDecider):
    def __init__(self, decision):
        super().__init__(lambda req: decision)
        self.calls = 0
        self._decision = decision

    def decide(self, request):
        self.calls += 1
        return self._decision


def routing_request():
    return DecisionRequest(
        kind="choice",
        question="Which seat should run this job?",
        context="job: summarise a public web page",
        options=("fast-seat", "frontier-seat"),
    )


class RouterTests(unittest.TestCase):

    def test_confident_cheap_decision_not_escalated(self):
        cheap = RulesDecider()
        cheap.add_keyword_choice_rule("summarise", "fast-seat", confidence=0.97)
        strong = SpyStrong(Choice(value="frontier-seat", confidence=0.99))
        router = Router(cheap=cheap, strong=strong, threshold=0.8)

        result = router.decide(routing_request())

        self.assertEqual(result.decision.value, "fast-seat")
        self.assertEqual(result.source, "cheap")
        self.assertFalse(result.escalated)
        self.assertEqual(strong.calls, 0)          # strong tier never touched
        self.assertEqual(len(router.log), 1)       # ...but the decision is logged
        self.assertEqual(router.log[0]["final_value"], "fast-seat")

    def test_low_confidence_decision_escalated(self):
        cheap = RulesDecider()  # no rules -> zero-confidence 'I don't know'
        strong = SpyStrong(Choice(value="frontier-seat", confidence=0.93))
        router = Router(cheap=cheap, strong=strong, threshold=0.8)

        result = router.decide(routing_request())

        self.assertTrue(result.escalated)
        self.assertEqual(result.source, "strong")
        self.assertEqual(result.decision.value, "frontier-seat")
        self.assertEqual(strong.calls, 1)
        self.assertEqual(result.cheap_decision.confidence, 0.0)

    def test_escalation_unavailable_without_strong_tier(self):
        router = Router(cheap=RulesDecider(), strong=None, threshold=0.8)
        result = router.decide(routing_request())
        self.assertFalse(result.escalated)
        self.assertTrue(result.escalation_unavailable)
        self.assertEqual(result.decision.confidence, 0.0)


def screen_router_that_clears_nothing():
    """A screen whose cheap tier never confidently clears a call."""
    return Router(cheap=RulesDecider(), strong=None, threshold=0.8)


class ToolGateTests(unittest.TestCase):

    def test_policy_denied_tool_call_blocked(self):
        gate = ToolGate(
            screen_router=screen_router_that_clears_nothing(),
            allow_tools={"read_file"},
            deny_tools={"shell"},
            deny_arg_patterns=[(None, r"rm\s+-rf")],
        )
        by_tool = gate.check(ToolCall(tool="shell", args={"cmd": "ls"}))
        self.assertEqual(by_tool.status, "denied")
        self.assertFalse(by_tool.allowed)

        by_args = gate.check(ToolCall(tool="exec",
                                      args={"cmd": "rm -rf /tmp/x"}))
        self.assertEqual(by_args.status, "denied")
        self.assertEqual(gate.pending(), [])       # denied calls are not queued

    def test_allow_listed_tool_passes_without_screen(self):
        gate = ToolGate(screen_router=screen_router_that_clears_nothing(),
                        allow_tools={"read_file"})
        result = gate.check(ToolCall(tool="read_file", args={"path": "a.md"}))
        self.assertEqual(result.status, "allowed")
        self.assertTrue(result.allowed)
        self.assertEqual(gate.pending(), [])

    def test_grey_zone_tool_call_queued_not_executed(self):
        gate = ToolGate(screen_router=screen_router_that_clears_nothing(),
                        allow_tools={"read_file"})
        result = gate.check(ToolCall(tool="send_email",
                                     args={"to": "lead@example.com"}))
        # Not allowed, not executed — parked for a human.
        self.assertEqual(result.status, "queued")
        self.assertFalse(result.allowed)
        self.assertIsNotNone(result.queue_id)
        pending = gate.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].call.tool, "send_email")

        # A human can resolve the record; resolving still executes nothing.
        entry = gate.approve(result.queue_id)
        self.assertEqual(entry.status, "approved")
        self.assertEqual(gate.pending(), [])
        self.assertFalse(hasattr(gate, "execute"))  # no execute path by design

    def test_grey_zone_cleared_by_confident_screen(self):
        screen_cheap = RulesDecider()
        # A screen that confidently clears read-only-looking calls.
        screen_cheap.add_flag_bool_rule("tool=fetch_page", value=True,
                                        confidence=0.95)
        router = Router(cheap=screen_cheap, strong=None, threshold=0.8)
        gate = ToolGate(screen_router=router, allow_tools=set())
        result = gate.check(ToolCall(tool="fetch_page",
                                     args={"url": "https://example.com"}))
        self.assertEqual(result.status, "allowed")
        self.assertEqual(gate.pending(), [])

    def test_grey_zone_queued_when_screen_says_unsafe(self):
        screen_cheap = RulesDecider()
        screen_cheap.add_flag_bool_rule("tool=fetch_page", value=True,
                                        confidence=0.95)
        router = Router(cheap=screen_cheap, strong=None, threshold=0.8)
        gate = ToolGate(screen_router=router, allow_tools=set())
        # 'send_email' does not match the screen's clearing rule -> escalates
        # nowhere (no strong tier) -> confidence 0 -> queued, fail closed.
        result = gate.check(ToolCall(tool="send_email", args={}))
        self.assertEqual(result.status, "queued")
        self.assertFalse(result.allowed)


if __name__ == "__main__":
    unittest.main()
