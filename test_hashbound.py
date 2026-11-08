"""
test_hashbound.py — the tamper tests ARE the product demo, as tests.

Run: python3 -m unittest test_hashbound -v

Centrepiece (test_tamper_*): queue a send, mutate the payload, try to
approve / execute — every path must BLOCK with tamper_blocked and a
diff. Before this module existed, the same sequence approved silently
(deep review 2026-11-08, Track A Q1).
"""

import hashlib
import json
import unittest

from decision_layer import ToolCall
from hashbound import (Executor, HashBoundGate, canonical_payload,
                       diff_payloads, payload_hash)


def send_call(to="lead@example.com", subject="Brief is ready"):
    return ToolCall(tool="send_email",
                    args={"to": to, "subject": subject,
                          "body": "The sourced brief is attached."},
                    context="publish run 1")


class HashTests(unittest.TestCase):

    def test_hash_is_sha256_hex_and_stable(self):
        h1 = payload_hash("send_email", {"to": "a@example.com", "n": 1})
        h2 = payload_hash("send_email", {"n": 1, "to": "a@example.com"})
        self.assertEqual(h1, h2)  # dict order never matters
        self.assertEqual(len(h1), 64)
        int(h1, 16)  # parses as hex

    def test_hash_changes_when_any_arg_changes(self):
        base = payload_hash("send_email", {"to": "a@example.com"})
        self.assertNotEqual(base, payload_hash(
            "send_email", {"to": "b@example.com"}))
        self.assertNotEqual(base, payload_hash(
            "submit_form", {"to": "a@example.com"}))
        self.assertNotEqual(base, payload_hash(
            "send_email", {"to": "a@example.com"}, context="other"))

    def test_canonical_matches_manual_sha256(self):
        canon = canonical_payload("t", {"a": 1})
        expect = hashlib.sha256(canon.encode()).hexdigest()
        self.assertEqual(payload_hash("t", {"a": 1}), expect)

    def test_diff_reports_changed_fields_only(self):
        diff = diff_payloads({"to": "a@x", "n": 1}, {"to": "b@x", "n": 1})
        self.assertEqual(len(diff), 1)
        self.assertEqual(diff[0]["field"], "to")
        self.assertEqual(diff[0]["approved"], "a@x")
        self.assertEqual(diff[0]["attempted"], "b@x")


class PolicyTests(unittest.TestCase):

    def setUp(self):
        self.gate = HashBoundGate()

    def test_allow_classes_pass_without_queue(self):
        for tool in ("read_file", "fetch_url", "write_file"):
            r = self.gate.check(ToolCall(tool=tool, args={"x": 1}))
            self.assertEqual(r.status, "allowed", tool)
        self.assertEqual(self.gate.pending(), [])

    def test_deny_classes_never_queue(self):
        for tool in ("spend", "delete_file", "read_secret",
                     "edit_gate_config", "payment"):
            r = self.gate.check(ToolCall(tool=tool, args={"x": 1}))
            self.assertEqual(r.status, "denied", tool)
            self.assertIn("DENY", r.reason)
        self.assertEqual(self.gate.pending(), [])

    def test_gate_classes_queue_with_hash(self):
        for tool in ("send_email", "publish_brief", "submit_form"):
            r = self.gate.check(ToolCall(tool=tool, args={"x": 1}))
            self.assertEqual(r.status, "queued", tool)
            self.assertIsNotNone(r.bound_hash)
            self.assertEqual(len(r.bound_hash), 64)
        self.assertEqual(len(self.gate.pending()), 3)

    def test_unknown_tool_fails_closed_to_queue(self):
        r = self.gate.check(ToolCall(tool="mystery_tool", args={}))
        self.assertEqual(r.status, "queued")

    def test_no_verdict_cache_fresh_entry_each_time(self):
        r1 = self.gate.check(send_call())
        r2 = self.gate.check(send_call())
        self.assertNotEqual(r1.queue_id, r2.queue_id)   # fresh verdict
        self.assertEqual(r1.bound_hash, r2.bound_hash)  # same payload
        self.assertEqual(len(self.gate.pending()), 2)


class TamperTests(unittest.TestCase):
    """The centrepiece. Each test is a beat of the demo video."""

    def setUp(self):
        self.gate = HashBoundGate()
        self.executor = Executor(self.gate)

    def test_approve_untampered_succeeds(self):
        r = self.gate.check(send_call())
        ok = self.gate.approve(r.queue_id, attempted=send_call())
        self.assertEqual(ok.status, "approved")
        self.assertEqual(ok.bound_hash, ok.attempted_hash)

    def test_tamper_in_place_mutation_blocks_approve(self):
        # The exact sequence from the deep review: queue, mutate the
        # queued payload's recipient, approve — must NOT go through.
        r = self.gate.check(send_call())
        entry = self.gate._find(r.queue_id)
        entry.call.args["to"] = "attacker@example.com"  # tamper!
        blocked = self.gate.approve(r.queue_id)
        self.assertEqual(blocked.status, "tamper_blocked")
        self.assertIn("TAMPER", blocked.reason)
        self.assertNotEqual(blocked.bound_hash, blocked.attempted_hash)
        fields = [d["field"] for d in blocked.tamper_diff]
        self.assertIn("to", fields)
        self.assertEqual(entry.status, "voided_tamper")

    def test_tamper_attempted_payload_blocks_approve(self):
        r = self.gate.check(send_call())
        evil = send_call(to="attacker@example.com")
        blocked = self.gate.approve(r.queue_id, attempted=evil)
        self.assertEqual(blocked.status, "tamper_blocked")
        self.assertEqual(blocked.tamper_diff[0]["approved"],
                         "lead@example.com")
        self.assertEqual(blocked.tamper_diff[0]["attempted"],
                         "attacker@example.com")

    def test_tamper_blocks_execution_even_after_honest_approval(self):
        r = self.gate.check(send_call())
        self.assertEqual(self.gate.approve(
            r.queue_id, attempted=send_call()).status, "approved")
        ran = []
        blocked = self.executor.execute(
            r.queue_id, send_call(to="attacker@example.com"),
            run=lambda c: ran.append(c) or "sent")
        self.assertEqual(blocked.status, "tamper_blocked")
        self.assertEqual(ran, [])  # the payload NEVER executed

    def test_execute_happy_path_runs_exact_approved_payload(self):
        r = self.gate.check(send_call())
        self.gate.approve(r.queue_id, attempted=send_call())
        done = self.executor.execute(r.queue_id, send_call(),
                                     run=lambda c: f"sent to {c.args['to']}")
        self.assertEqual(done.status, "executed")
        self.assertIn("lead@example.com",
                      self.executor.executed[0]["output"])

    def test_unapproved_entry_cannot_execute(self):
        r = self.gate.check(send_call())
        denied = self.executor.execute(r.queue_id, send_call(),
                                       run=lambda c: "sent")
        self.assertEqual(denied.status, "denied")
        self.assertEqual(self.executor.executed, [])

    def test_voided_entry_stays_voided(self):
        r = self.gate.check(send_call())
        self.gate.approve(r.queue_id,
                          attempted=send_call(to="evil@example.com"))
        again = self.executor.execute(r.queue_id, send_call(),
                                      run=lambda c: "sent")
        self.assertEqual(again.status, "tamper_blocked")
        self.assertEqual(self.executor.executed, [])

    def test_reject_works_and_blocks_execution(self):
        r = self.gate.check(send_call())
        self.assertEqual(self.gate.reject(r.queue_id).status, "rejected")
        denied = self.executor.execute(r.queue_id, send_call(),
                                       run=lambda c: "sent")
        self.assertEqual(denied.status, "denied")

    def test_ledger_records_queue_and_tamper_events(self):
        r = self.gate.check(send_call())
        self.gate.approve(r.queue_id,
                          attempted=send_call(to="evil@example.com"))
        events = [e["event"] for e in self.gate.ledger]
        self.assertIn("queued", events)
        self.assertIn("tamper_blocked", events)
        tamper = [e for e in self.gate.ledger
                  if e["event"] == "tamper_blocked"][0]
        self.assertEqual(len(tamper["bound_hash"]), 64)
        self.assertTrue(tamper["diff"])

    def test_hostile_injection_payloads_are_denied_by_class(self):
        # The SPEC containment beat, at the gate layer: an injected
        # instruction that becomes a secrets send or a delete is a
        # DENY class — it never even reaches the queue.
        for tool, args in (
            ("read_secret", {"name": "VULTR_INFERENCE_API_KEY"}),
            ("delete_workspace", {"path": "/"}),
            ("exfiltrate", {"to": "attacker@example.com"}),
        ):
            r = self.gate.check(ToolCall(tool=tool, args=args,
                                         context="injected source page"))
            self.assertEqual(r.status, "denied", tool)


if __name__ == "__main__":
    unittest.main()
