"""
test_probes.py — unit tests for the approval-layer hardening:
one-time execution (replay), stale approvals (TTL), approval-token
reuse, self-approval, decimal-shift via the hash bind, and the
hash-chained receipt ledger. Plus an integration test that the
probe runner itself reports all PASS.

Run: python3 -m unittest test_probes -v
"""

import copy
import time
import unittest

from decision_layer import ToolCall
from hashbound import (Executor, HashBoundGate, verify_ledger_chain)
import probes as probe_mod


def send_call(to="lead@example.com"):
    return ToolCall(tool="send_email",
                    args={"to": to, "subject": "Brief", "body": "x"},
                    context="probe tests")


def form_call(amount):
    return ToolCall(tool="submit_form",
                    args={"to": "vendor@example.com", "amount": amount},
                    context="probe tests")


class ReplayTests(unittest.TestCase):

    def setUp(self):
        self.gate = HashBoundGate()
        self.ex = Executor(self.gate)

    def test_execute_twice_second_is_replay_blocked(self):
        r = self.gate.check(send_call())
        self.gate.approve(r.queue_id, attempted=send_call())
        first = self.ex.execute(r.queue_id, send_call(),
                                run=lambda c: "sent")
        self.assertEqual(first.status, "executed")
        second = self.ex.execute(r.queue_id, send_call(),
                                 run=lambda c: "sent")
        self.assertEqual(second.status, "replay_blocked")
        self.assertEqual(len(self.ex.executed), 1)  # ran exactly once

    def test_approval_issues_one_time_token_and_consumes_it(self):
        r = self.gate.check(send_call())
        ok = self.gate.approve(r.queue_id, attempted=send_call())
        self.assertTrue(ok.approval_token)
        entry = self.gate._find(r.queue_id)
        self.assertEqual(entry.approval_token, ok.approval_token)
        self.assertFalse(entry.token_consumed)
        self.ex.execute(r.queue_id, send_call(), run=lambda c: "sent",
                        token=ok.approval_token)
        self.assertTrue(entry.token_consumed)


class ApprovalReuseTests(unittest.TestCase):

    def test_foreign_token_is_refused_and_entry_survives(self):
        gate = HashBoundGate()
        ex = Executor(gate)
        ra = gate.check(send_call(to="a@example.com"))
        rb = gate.check(send_call(to="b@example.com"))
        aa = gate.approve(ra.queue_id,
                          attempted=send_call(to="a@example.com"))
        gate.approve(rb.queue_id, attempted=send_call(to="b@example.com"))
        refused = ex.execute(rb.queue_id, send_call(to="b@example.com"),
                             run=lambda c: "sent",
                             token=aa.approval_token)
        self.assertEqual(refused.status, "approval_reuse_blocked")
        self.assertEqual(ex.executed, [])
        # The refusal consumed nothing: B still executes cleanly.
        done = ex.execute(rb.queue_id, send_call(to="b@example.com"),
                          run=lambda c: "sent")
        self.assertEqual(done.status, "executed")

    def test_correct_token_executes(self):
        gate = HashBoundGate()
        ex = Executor(gate)
        r = gate.check(send_call())
        ok = gate.approve(r.queue_id, attempted=send_call())
        done = ex.execute(r.queue_id, send_call(), run=lambda c: "sent",
                          token=ok.approval_token)
        self.assertEqual(done.status, "executed")


class StaleApprovalTests(unittest.TestCase):

    def test_pending_entry_expires_and_cannot_be_approved(self):
        gate = HashBoundGate(ttl_seconds=0.05)
        r = gate.check(send_call())
        time.sleep(0.07)
        stale = gate.approve(r.queue_id, attempted=send_call())
        self.assertEqual(stale.status, "expired")
        self.assertEqual(gate._find(r.queue_id).status, "expired")

    def test_approved_entry_expires_before_execution(self):
        gate = HashBoundGate(ttl_seconds=0.05)
        ex = Executor(gate)
        r = gate.check(send_call())
        self.assertEqual(gate.approve(
            r.queue_id, attempted=send_call()).status, "approved")
        time.sleep(0.07)
        stale = ex.execute(r.queue_id, send_call(), run=lambda c: "sent")
        self.assertEqual(stale.status, "expired")
        self.assertEqual(ex.executed, [])

    def test_ttl_is_configurable_and_defaults_to_300(self):
        self.assertEqual(HashBoundGate().ttl_seconds, 300.0)
        self.assertEqual(HashBoundGate(ttl_seconds=42).ttl_seconds, 42.0)

    def test_fresh_entry_within_ttl_still_works(self):
        gate = HashBoundGate(ttl_seconds=60)
        r = gate.check(send_call())
        self.assertEqual(gate.approve(
            r.queue_id, attempted=send_call()).status, "approved")


class SelfApprovalTests(unittest.TestCase):

    def test_proposer_cannot_approve_own_action(self):
        gate = HashBoundGate()
        r = gate.check(send_call(), proposer="agent-1")
        blocked = gate.approve(r.queue_id, attempted=send_call(),
                               approver="agent-1")
        self.assertEqual(blocked.status, "self_approval_blocked")
        self.assertEqual(gate._find(r.queue_id).status, "pending")

    def test_distinct_approver_can_still_approve(self):
        gate = HashBoundGate()
        r = gate.check(send_call(), proposer="agent-1")
        gate.approve(r.queue_id, attempted=send_call(),
                     approver="agent-1")
        ok = gate.approve(r.queue_id, attempted=send_call(),
                          approver="ops-lead")
        self.assertEqual(ok.status, "approved")
        self.assertEqual(gate._find(r.queue_id).approver, "ops-lead")

    def test_anonymous_flow_unchanged(self):
        # No proposer recorded + no approver named: the pre-existing
        # demo flow must not be affected.
        gate = HashBoundGate()
        r = gate.check(send_call())
        self.assertEqual(gate.approve(
            r.queue_id, attempted=send_call()).status, "approved")


class DecimalShiftTests(unittest.TestCase):

    def test_decimal_shift_caught_by_hash_bind_with_diff(self):
        gate = HashBoundGate()
        ex = Executor(gate)
        r = gate.check(form_call("100.00"))
        gate.approve(r.queue_id, attempted=form_call("100.00"))
        blocked = ex.execute(r.queue_id, form_call("10000.00"),
                             run=lambda c: "paid")
        self.assertEqual(blocked.status, "tamper_blocked")
        diff = {d["field"]: d for d in blocked.tamper_diff}
        self.assertEqual(diff["amount"]["approved"], "100.00")
        self.assertEqual(diff["amount"]["attempted"], "10000.00")
        self.assertEqual(ex.executed, [])


class LedgerChainTests(unittest.TestCase):

    def _session(self):
        gate = HashBoundGate()
        ex = Executor(gate)
        r = gate.check(send_call())
        gate.approve(r.queue_id,
                     attempted=send_call(to="evil@example.com"))
        r2 = gate.check(send_call())
        gate.approve(r2.queue_id, attempted=send_call())
        ex.execute(r2.queue_id, send_call(), run=lambda c: "sent")
        return gate

    def test_chain_verifies_on_honest_ledger(self):
        gate = self._session()
        ok, bad = verify_ledger_chain(gate.ledger)
        self.assertTrue(ok)
        self.assertIsNone(bad)
        self.assertEqual(gate.ledger[0]["prev_hash"], "0" * 64)
        for prev, cur in zip(gate.ledger, gate.ledger[1:]):
            self.assertEqual(cur["prev_hash"], prev["receipt_hash"])

    def test_mutating_a_historical_receipt_breaks_the_chain(self):
        gate = self._session()
        forged = copy.deepcopy(gate.ledger)
        forged[1]["event"] = "approved"  # rewrite history
        ok, bad = verify_ledger_chain(forged)
        self.assertFalse(ok)
        self.assertEqual(bad, 1)

    def test_deleting_a_receipt_breaks_the_chain(self):
        gate = self._session()
        forged = copy.deepcopy(gate.ledger)
        del forged[1]
        ok, _ = verify_ledger_chain(forged)
        self.assertFalse(ok)

    def test_empty_ledger_verifies(self):
        self.assertEqual(verify_ledger_chain([]), (True, None))


class ProbeRunnerTests(unittest.TestCase):

    def test_probe_runner_all_pass(self):
        results = probe_mod.run_probes()
        self.assertEqual(len(results), 7)
        for row in results:
            self.assertEqual(row["result"], "PASS", row)


if __name__ == "__main__":
    unittest.main()
