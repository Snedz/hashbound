"""
hashbound.py — HashBound: hash-bound human approval for agent actions.

The differentiator, in one property:

    An approval is bound to the SHA-256 hash of the EXACT action payload
    that was queued. If the payload changes after approval is requested —
    by anyone, for any reason — the approval VOIDS. The executor re-hashes
    the payload it is about to run and compares it to the queued hash.
    Mismatch -> DENY, with an approved-vs-attempted diff. No exceptions.

Why this exists: a fleet audit found a reviewer whose verdict cache
returned stored ACCEPTs verbatim, so a verdict earned by one payload
could be replayed onto a different one. This module has NO verdict
cache. Every verdict is computed fresh, and every queued verdict is
bound to a payload hash at queue time.

Built on the proven decision_layer.ToolGate semantics (deterministic
policy -> classifier screen -> human-approval queue, fail-closed, the
gate itself has no execute path). The executor here is a separate
object (Executor) that only runs a payload whose hash still matches
an approved entry — mirroring the fleet rule that screening is not
consent and consent is not execution.

Stdlib only. No network. The only LLM path in the system is
vultr_inference.py.
"""

from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from decision_layer import ToolCall

# ---------------------------------------------------------------------------
# Canonicalisation + hashing
# ---------------------------------------------------------------------------

def canonical_payload(tool: str, args: dict, context: str = "") -> str:
    """One stable string for a payload. Dict key order never matters."""
    return json.dumps(
        {"tool": tool, "args": args, "context": context},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    )


def payload_hash(tool: str, args: dict, context: str = "") -> str:
    return hashlib.sha256(
        canonical_payload(tool, args, context).encode("utf-8")
    ).hexdigest()


#: prev_hash of the first receipt in any ledger.
GENESIS_HASH = "0" * 64


def receipt_hash(rec: dict) -> str:
    """SHA-256 over a ledger receipt, excluding its own hash field.

    The receipt's prev_hash is part of the hashed content — that is
    what makes the chain: change any earlier receipt and its hash no
    longer matches what the next receipt recorded.
    """
    body = {k: v for k, v in rec.items() if k != "receipt_hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def verify_ledger_chain(records: list) -> tuple:
    """Verify a hash-chained receipt ledger.

    Returns (ok, bad_index): ok=True iff every receipt's prev_hash
    matches the previous receipt's hash AND every receipt_hash
    recomputes exactly. bad_index is the first failing position
    (None when ok).
    """
    prev = GENESIS_HASH
    for i, rec in enumerate(records):
        if rec.get("prev_hash") != prev:
            return False, i
        if rec.get("receipt_hash") != receipt_hash(rec):
            return False, i
        prev = rec["receipt_hash"]
    return True, None


def diff_payloads(approved: dict, attempted: dict) -> list:
    """Field-level approved-vs-attempted diff, for the tamper page.

    Returns a list of {"field", "approved", "attempted"} for every key
    whose value differs (including keys present on only one side).
    """
    out = []
    for key in sorted(set(approved) | set(attempted)):
        a = approved.get(key, "<absent>")
        b = attempted.get(key, "<absent>")
        if a != b:
            out.append({"field": key, "approved": a, "attempted": b})
    return out


# ---------------------------------------------------------------------------
# Action classes — the fleet's 8-class policy (SPEC §b), verbatim defaults
# ---------------------------------------------------------------------------

TOOL_CLASS = {
    "read_file": "read",
    "fetch_url": "read",
    "list_files": "read",
    "write_file": "local_write",
    "send_email": "external_send",
    "submit_form": "external_send",
    "publish_brief": "deploy_publish",
    "deploy": "deploy_publish",
    "spend": "spend",
    "payment": "spend",
    "paypal.capture": "spend",
    "delete_file": "delete",
    "delete_workspace": "delete",
    "read_secret": "secrets",
    "exfiltrate": "secrets",
    "edit_gate_config": "gate_self_mod",
    "edit_policy": "gate_self_mod",
}

CLASS_DEFAULT = {
    "read": "allow",            # Read ALLOW
    "local_write": "allow",     # Local write ALLOW (workspace-bounded in app)
    "external_send": "gate",    # External send GATE
    "spend": "deny",            # Spend DENY
    "deploy_publish": "gate",   # Deploy / publish GATE
    "delete": "deny",           # Delete / destructive DENY
    "secrets": "deny",          # Secrets access DENY
    "gate_self_mod": "deny",    # Gate self-modification DENY
}


def classify(tool: str) -> str:
    return TOOL_CLASS.get(tool, "unknown")


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass
class BoundEntry:
    id: str
    call: ToolCall                    # the live (mutable) queued payload
    snapshot_args: dict               # deep copy taken at queue time
    snapshot_context: str
    bound_hash: str                   # hash of the snapshot, at queue time
    action_class: str
    reason: str
    status: str = "pending"           # pending | approved | rejected |
                                      # voided_tamper | executed | expired
    created: float = field(default_factory=time.time)
    resolved: Optional[float] = None
    tamper_diff: list = field(default_factory=list)
    attempted_hash: Optional[str] = None
    # -- approval-layer hardening (probe suite, 2026-11-08) ----------------
    proposer: str = ""                # who queued the action
    expires_at: float = 0.0           # pending entries die at created+TTL
    approver: Optional[str] = None    # who approved (never == proposer)
    approved_at: Optional[float] = None
    approval_expires_at: Optional[float] = None  # approvals die at +TTL too
    approval_token: Optional[str] = None  # one-time token issued at approve
    token_consumed: bool = False      # a spent token can never be re-spent


@dataclass
class BoundResult:
    status: str          # allowed | denied | queued | approved |
                         # tamper_blocked | rejected | executed |
                         # expired | replay_blocked |
                         # approval_reuse_blocked | self_approval_blocked
    reason: str
    queue_id: Optional[str] = None
    bound_hash: Optional[str] = None
    attempted_hash: Optional[str] = None
    tamper_diff: list = field(default_factory=list)
    approval_token: Optional[str] = None
    expires_at: Optional[float] = None

    @property
    def allowed(self) -> bool:
        return self.status in ("allowed", "approved", "executed")


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

class HashBoundGate:
    """Deterministic policy first; GATE classes queue WITH a hash binding;
    DENY classes never queue; unknown tools fail closed to the queue.

    An optional classifier screen (a Callable returning bool) may clear
    unknown tools only — it can never clear a GATE or DENY class, and a
    screen error fails closed to the queue.
    """

    #: Pending approvals and issued approvals both die after this many
    #: seconds (configurable). Short by default: an approval is a
    #: decision about a moment, not a standing permission.
    DEFAULT_TTL_SECONDS = 300.0

    def __init__(self, screen: Optional[Callable[[ToolCall], bool]] = None,
                 ledger_path: Optional[str] = None,
                 class_defaults: Optional[dict] = None,
                 ttl_seconds: float = DEFAULT_TTL_SECONDS):
        self.screen = screen
        self.ledger_path = ledger_path
        self.class_defaults = dict(CLASS_DEFAULT)
        if class_defaults:
            self.class_defaults.update(class_defaults)
        self.ttl_seconds = float(ttl_seconds)
        self.queue: list = []
        self.ledger: list = []
        self._last_receipt_hash = GENESIS_HASH

    # -- ledger (hash-chained, tamper-evident) ------------------------------

    def _log(self, event: str, entry: Optional[BoundEntry], **extra):
        rec = {"event": event, "ts": time.time(), **extra}
        if entry is not None:
            rec.update({"id": entry.id, "tool": entry.call.tool,
                        "bound_hash": entry.bound_hash,
                        "status": entry.status})
        # Chain this receipt to the previous one: mutating any
        # historical receipt breaks every later link (see
        # verify_ledger_chain).
        rec["prev_hash"] = self._last_receipt_hash
        rec["receipt_hash"] = receipt_hash(rec)
        self._last_receipt_hash = rec["receipt_hash"]
        self.ledger.append(rec)
        if self.ledger_path:
            with open(self.ledger_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")

    # -- main entry ----------------------------------------------------------

    def check(self, call: ToolCall, proposer: str = "") -> BoundResult:
        action_class = classify(call.tool)
        default = self.class_defaults.get(action_class, "gate")

        if default == "deny":
            result = BoundResult(
                status="denied",
                reason=(f"DENY — class '{action_class}': deterministic "
                        f"policy denies '{call.tool}' before any model "
                        f"is consulted"),
                bound_hash=payload_hash(call.tool, call.args, call.context),
            )
            self._log("denied", None, tool=call.tool,
                      bound_hash=result.bound_hash, reason=result.reason)
            return result

        if default == "allow":
            return BoundResult(
                status="allowed",
                reason=f"ALLOW — class '{action_class}' by policy",
                bound_hash=payload_hash(call.tool, call.args, call.context),
            )

        if action_class == "unknown" and self.screen is not None:
            try:
                if self.screen(call):
                    return BoundResult(
                        status="allowed",
                        reason="classifier screen cleared unknown tool "
                               f"'{call.tool}'",
                        bound_hash=payload_hash(call.tool, call.args,
                                                call.context))
            except Exception:
                pass  # fail closed: fall through to the queue

        # GATE (and unknown / screen-uncleared): queue, hash-bound NOW.
        bound = payload_hash(call.tool, call.args, call.context)
        entry = BoundEntry(
            id=uuid.uuid4().hex[:12],
            call=copy.deepcopy(call),
            snapshot_args=copy.deepcopy(call.args),
            snapshot_context=call.context,
            bound_hash=bound,
            action_class=action_class if action_class != "unknown"
            else "unknown",
            reason=(f"GATE — class '{action_class}': '{call.tool}' waits "
                    f"for a human approver; approval is bound to payload "
                    f"hash {bound[:16]}…"),
            proposer=proposer,
        )
        entry.expires_at = entry.created + self.ttl_seconds
        self.queue.append(entry)
        self._log("queued", entry)
        return BoundResult(status="queued", reason=entry.reason,
                           queue_id=entry.id, bound_hash=bound,
                           expires_at=entry.expires_at)

    # -- expiry ---------------------------------------------------------------

    def _check_expiry(self, entry: BoundEntry) -> bool:
        """Fail closed on stale work. A pending entry past its TTL, or
        an approved entry past its approval TTL, becomes 'expired':
        the action must be re-queued and re-approved fresh."""
        now = time.time()
        if entry.status == "pending" and entry.expires_at \
                and now > entry.expires_at:
            entry.status = "expired"
            entry.resolved = now
            self._log("approval_expired", entry,
                      phase="pending")
            return True
        if entry.status == "approved" and entry.approval_expires_at \
                and now > entry.approval_expires_at:
            entry.status = "expired"
            entry.resolved = now
            self._log("approval_expired", entry,
                      phase="approved")
            return True
        return False

    def _expired_result(self, entry: BoundEntry) -> BoundResult:
        return BoundResult(
            status="expired",
            reason=("DENY — STALE: this approval window has expired. "
                    "Approvals are decisions about a moment, not "
                    "standing permissions; re-queue and re-approve "
                    "the action fresh."),
            queue_id=entry.id, bound_hash=entry.bound_hash,
            expires_at=entry.expires_at)

    # -- approval, with hash verification ------------------------------------

    def _find(self, entry_id: str) -> BoundEntry:
        for entry in self.queue:
            if entry.id == entry_id:
                return entry
        raise KeyError(f"no queue entry {entry_id}")

    def _verify(self, entry: BoundEntry,
                attempted: Optional[ToolCall]) -> Optional[BoundResult]:
        """Return a tamper_blocked result if anything changed, else None.

        Two checks, both must pass:
        1. The queued payload itself was not mutated in place after
           queueing (re-hash the live entry vs. its snapshot hash).
        2. If the caller presents the payload it intends to execute,
           that payload's hash must equal the bound hash.
        """
        live_hash = payload_hash(entry.call.tool, entry.call.args,
                                 entry.call.context)
        if live_hash != entry.bound_hash:
            diff = diff_payloads(entry.snapshot_args, entry.call.args)
            if entry.call.tool != entry.snapshot_args.get("__tool__", entry.call.tool):
                pass
            entry.status = "voided_tamper"
            entry.resolved = time.time()
            entry.tamper_diff = diff
            entry.attempted_hash = live_hash
            self._log("tamper_blocked", entry, attempted_hash=live_hash,
                      diff=diff)
            return BoundResult(
                status="tamper_blocked",
                reason=("DENY — TAMPER: the queued payload changed after "
                        "it was queued. Its current hash does not match "
                        "the hash the approval was requested for, so the "
                        "approval is VOID. The action must be re-queued "
                        "and re-approved as the payload it now is."),
                queue_id=entry.id, bound_hash=entry.bound_hash,
                attempted_hash=live_hash, tamper_diff=diff)

        if attempted is not None:
            att_hash = payload_hash(attempted.tool, attempted.args,
                                    attempted.context)
            entry.attempted_hash = att_hash
            if att_hash != entry.bound_hash:
                diff = diff_payloads(entry.snapshot_args, attempted.args)
                if attempted.tool != entry.call.tool:
                    diff = [{"field": "__tool__",
                             "approved": entry.call.tool,
                             "attempted": attempted.tool}] + diff
                entry.status = "voided_tamper"
                entry.resolved = time.time()
                entry.tamper_diff = diff
                self._log("tamper_blocked", entry, attempted_hash=att_hash,
                          diff=diff)
                return BoundResult(
                    status="tamper_blocked",
                    reason=("DENY — TAMPER: the payload presented for "
                            "execution does not match the approved "
                            "payload hash. Approval VOID; re-queue and "
                            "re-approve the payload as presented."),
                    queue_id=entry.id, bound_hash=entry.bound_hash,
                    attempted_hash=att_hash, tamper_diff=diff)
        return None

    def approve(self, entry_id: str,
                attempted: Optional[ToolCall] = None,
                approver: Optional[str] = None) -> BoundResult:
        entry = self._find(entry_id)
        if self._check_expiry(entry):
            return self._expired_result(entry)
        if entry.status != "pending":
            return BoundResult(
                status="denied",
                reason=f"entry {entry_id} is '{entry.status}', not pending",
                queue_id=entry.id, bound_hash=entry.bound_hash)
        # Self-approval is not approval: the proposer of an action can
        # never be its approver. Blocked, but the entry stays pending —
        # a different approver can still approve it.
        if approver is not None and entry.proposer \
                and approver == entry.proposer:
            self._log("self_approval_blocked", entry, approver=approver)
            return BoundResult(
                status="self_approval_blocked",
                reason=("DENY — SELF-APPROVAL: the proposer of an "
                        "action cannot approve it. A second, distinct "
                        "approver is required."),
                queue_id=entry.id, bound_hash=entry.bound_hash)
        blocked = self._verify(entry, attempted)
        if blocked is not None:
            return blocked
        entry.status = "approved"
        entry.resolved = time.time()
        entry.approver = approver
        entry.approved_at = entry.resolved
        entry.approval_expires_at = entry.resolved + self.ttl_seconds
        # One-time execution token: minted here, consumed by the first
        # successful execute, worthless thereafter.
        entry.approval_token = uuid.uuid4().hex
        entry.token_consumed = False
        self._log("approved", entry)
        return BoundResult(
            status="approved",
            reason=("Approved — payload hash verified unchanged: "
                    f"{entry.bound_hash[:16]}…"),
            queue_id=entry.id, bound_hash=entry.bound_hash,
            attempted_hash=entry.bound_hash,
            approval_token=entry.approval_token,
            expires_at=entry.approval_expires_at)

    def reject(self, entry_id: str) -> BoundResult:
        entry = self._find(entry_id)
        entry.status = "rejected"
        entry.resolved = time.time()
        self._log("rejected", entry)
        return BoundResult(status="rejected", reason="Rejected by approver",
                           queue_id=entry.id, bound_hash=entry.bound_hash)

    def pending(self) -> list:
        return [e for e in self.queue if e.status == "pending"]


class Executor:
    """The ONLY execute path — and it re-verifies the hash at run time.

    Approval alone is never enough: execute() re-hashes the payload it
    is handed and refuses (DENY) unless it matches the bound hash of an
    APPROVED entry. This is the second half of the tamper demo: even an
    approval obtained honestly cannot be spent on a different payload.
    """

    def __init__(self, gate: HashBoundGate):
        self.gate = gate
        self.executed: list = []

    def execute(self, entry_id: str, attempted: ToolCall,
                run: Callable[[ToolCall], object],
                token: Optional[str] = None) -> BoundResult:
        entry = self.gate._find(entry_id)
        if entry.status == "voided_tamper":
            return BoundResult(
                status="tamper_blocked",
                reason="DENY — this approval was already voided by a "
                       "hash mismatch.",
                queue_id=entry.id, bound_hash=entry.bound_hash,
                attempted_hash=entry.attempted_hash,
                tamper_diff=entry.tamper_diff)
        # Replay: the one-time execution nonce is spent. An executed
        # entry can never execute again — re-queue for a new approval.
        if entry.status == "executed" or entry.token_consumed:
            self.gate._log("replay_blocked", entry)
            return BoundResult(
                status="replay_blocked",
                reason=("DENY — REPLAY: this approval has already been "
                        "executed. Approvals are one-time: the "
                        "execution nonce is consumed. Re-queue and "
                        "re-approve for another run."),
                queue_id=entry.id, bound_hash=entry.bound_hash)
        # Approval reuse: a presented token must be THIS entry's live
        # token. A token minted for another entry — or a spent/forged
        # one — is refused and never consumes anything.
        if token is not None and entry.approval_token is not None \
                and token != entry.approval_token:
            self.gate._log("approval_reuse_blocked", entry)
            return BoundResult(
                status="approval_reuse_blocked",
                reason=("DENY — APPROVAL REUSE: the presented approval "
                        "token is not this entry's live one-time "
                        "token. Approval tokens are bound to a single "
                        "queued action and die on first use."),
                queue_id=entry.id, bound_hash=entry.bound_hash)
        if self.gate._check_expiry(entry):
            return self.gate._expired_result(entry)
        if entry.status != "approved":
            return BoundResult(
                status="denied",
                reason=(f"DENY — entry is '{entry.status}'; only an "
                        f"approved, hash-verified entry can execute"),
                queue_id=entry.id, bound_hash=entry.bound_hash)
        blocked = self.gate._verify(entry, attempted)
        if blocked is not None:
            return blocked
        output = run(attempted)
        entry.status = "executed"
        entry.token_consumed = True
        self.executed.append({"id": entry.id, "tool": attempted.tool,
                              "output": output, "ts": time.time()})
        self.gate._log("executed", entry)
        return BoundResult(
            status="executed",
            reason="Executed — hash verified at approval AND at execution",
            queue_id=entry.id, bound_hash=entry.bound_hash,
            attempted_hash=entry.bound_hash)
