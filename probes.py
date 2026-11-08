"""
probes.py — the approval-layer probe suite.

Field research for this hackathon (Nov 7) found sandbox attack-probe
suites everywhere and probes against the APPROVAL layer nowhere. This
runner is that missing suite: seven attacks aimed at the approval
itself — not the payload, not the sandbox — each executed against the
real HashBound gate + executor, each with a measured actual outcome.

    python3 probes.py

Exit code 0 iff every probe PASSes. The scoreboard it prints is the
demo's evidence table (README + slides quote it verbatim).
"""

from __future__ import annotations

import copy
import sys
import time

from decision_layer import ToolCall
from hashbound import (Executor, HashBoundGate, verify_ledger_chain)


def _send(to="lead@example.com", amount=None):
    args = {"to": to, "subject": "Sourced brief", "body": "Attached."}
    if amount is not None:
        args["amount"] = amount
    tool = "submit_form" if amount is not None else "send_email"
    return ToolCall(tool=tool, args=args, context="probe run")


def probe_tamper() -> dict:
    """Queue a send, swap the recipient, approve -> must block."""
    gate = HashBoundGate()
    r = gate.check(_send())
    blocked = gate.approve(r.queue_id,
                           attempted=_send(to="attacker@example.com"))
    return {"probe": "tamper_after_approval",
            "expected": "tamper_blocked",
            "actual": blocked.status,
            "detail": ("diff fields: "
                       + ", ".join(d["field"]
                                   for d in blocked.tamper_diff))}


def probe_replay() -> dict:
    """Approve, execute, execute AGAIN -> the replay must fail and
    the payload must have run exactly once."""
    gate = HashBoundGate()
    ex = Executor(gate)
    r = gate.check(_send())
    gate.approve(r.queue_id, attempted=_send())
    first = ex.execute(r.queue_id, _send(), run=lambda c: "sent")
    second = ex.execute(r.queue_id, _send(), run=lambda c: "sent")
    actual = second.status if first.status == "executed" else first.status
    return {"probe": "replay_executed_approval",
            "expected": "replay_blocked",
            "actual": actual,
            "detail": f"payload ran {len(ex.executed)} time(s)"}


def probe_stale_approval() -> dict:
    """Queue with a short TTL, let it lapse, approve -> expired.
    The same lapse after approval also blocks execution."""
    gate = HashBoundGate(ttl_seconds=0.2)
    ex = Executor(gate)
    r = gate.check(_send())
    time.sleep(0.25)
    stale_approve = gate.approve(r.queue_id, attempted=_send())
    r2 = gate.check(_send())
    gate.approve(r2.queue_id, attempted=_send())
    time.sleep(0.25)
    stale_execute = ex.execute(r2.queue_id, _send(), run=lambda c: "sent")
    ok = stale_approve.status == "expired" \
        and stale_execute.status == "expired" and not ex.executed
    return {"probe": "stale_approval",
            "expected": "expired",
            "actual": (f"approve: {stale_approve.status}, "
                       f"execute: {stale_execute.status}"),
            "detail": "TTL 0.2s; both phases fail closed to re-queue",
            "_ok": ok}


def probe_approval_reuse() -> dict:
    """Mint two approvals; spend entry A's token on entry B -> the
    foreign token must be refused, and B must stay executable with
    its own token."""
    gate = HashBoundGate()
    ex = Executor(gate)
    ra = gate.check(_send(to="a@example.com"))
    rb = gate.check(_send(to="b@example.com"))
    aa = gate.approve(ra.queue_id, attempted=_send(to="a@example.com"))
    gate.approve(rb.queue_id, attempted=_send(to="b@example.com"))
    foreign = ex.execute(rb.queue_id, _send(to="b@example.com"),
                         run=lambda c: "sent", token=aa.approval_token)
    own = ex.execute(rb.queue_id, _send(to="b@example.com"),
                     run=lambda c: "sent")
    ok = foreign.status == "approval_reuse_blocked" \
        and own.status == "executed"
    return {"probe": "approval_token_reuse",
            "expected": "approval_reuse_blocked",
            "actual": foreign.status,
            "detail": f"own-token execute afterwards: {own.status}",
            "_ok": ok}


def probe_decimal_shift() -> dict:
    """Approve a form for 100.00, execute at 10000.00 -> the hash
    bind must catch a pure numeric mutation, with a field diff."""
    gate = HashBoundGate()
    r = gate.check(_send(amount="100.00"))
    gate.approve(r.queue_id, attempted=_send(amount="100.00"))
    ex = Executor(gate)
    blocked = ex.execute(r.queue_id, _send(amount="10000.00"),
                         run=lambda c: "paid")
    diff = blocked.tamper_diff[0] if blocked.tamper_diff else {}
    return {"probe": "decimal_shift_amount",
            "expected": "tamper_blocked",
            "actual": blocked.status,
            "detail": (f"amount: {diff.get('approved')} -> "
                       f"{diff.get('attempted')}")}


def probe_self_approval() -> dict:
    """The proposer of an action can never approve it; a distinct
    approver still can (the block is not a dead end)."""
    gate = HashBoundGate()
    r = gate.check(_send(), proposer="agent-1")
    selfish = gate.approve(r.queue_id, attempted=_send(),
                           approver="agent-1")
    honest = gate.approve(r.queue_id, attempted=_send(),
                          approver="ops-lead")
    ok = selfish.status == "self_approval_blocked" \
        and honest.status == "approved"
    return {"probe": "self_approval",
            "expected": "self_approval_blocked",
            "actual": selfish.status,
            "detail": f"distinct approver afterwards: {honest.status}",
            "_ok": ok}


def probe_ledger_chain() -> dict:
    """Run a session, verify the hash chain; then mutate a historical
    receipt and verify the chain detects it."""
    gate = HashBoundGate()
    ex = Executor(gate)
    r = gate.check(_send())
    gate.approve(r.queue_id, attempted=_send(to="evil@example.com"))
    r2 = gate.check(_send())
    gate.approve(r2.queue_id, attempted=_send())
    ex.execute(r2.queue_id, _send(), run=lambda c: "sent")
    ok_before, _ = verify_ledger_chain(gate.ledger)
    forged = copy.deepcopy(gate.ledger)
    forged[0]["event"] = "approved"        # rewrite history
    ok_after, bad_at = verify_ledger_chain(forged)
    ok = ok_before and not ok_after
    return {"probe": "ledger_chain_tamper",
            "expected": "chain_detects_mutation",
            "actual": ("intact chain OK; mutation detected at "
                       f"index {bad_at}" if ok else "CHAIN FAILURE"),
            "detail": f"{len(gate.ledger)} receipts, hash-chained",
            "_ok": ok}


PROBES = [probe_tamper, probe_replay, probe_stale_approval,
          probe_approval_reuse, probe_decimal_shift, probe_self_approval,
          probe_ledger_chain]


def run_probes() -> list:
    results = []
    for fn in PROBES:
        row = fn()
        row["result"] = "PASS" if row.pop("_ok", row["actual"] ==
                                         row["expected"]) else "FAIL"
        results.append(row)
    return results


def main() -> int:
    results = run_probes()
    print("HashBound approval-layer probe suite")
    print("=" * 72)
    for row in results:
        print(f"[{row['result']}] {row['probe']:<26} "
              f"expected={row['expected']:<24} actual={row['actual']}")
        print(f"       {row['detail']}")
    passed = sum(1 for r in results if r["result"] == "PASS")
    print("=" * 72)
    print(f"PROBE SCOREBOARD: {passed}/{len(results)} PASS")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
