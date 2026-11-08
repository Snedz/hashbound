"""
decision_layer.py — reference implementation of the "decision layer" pattern.

Kernel source: TypeSafe AI's Jev (intel note
~/workspace/intel/2026-11-03-instagram-raycfu-jev-agent-harness.md, registry
G-ADD-30). Jev itself is a paid, early-access API and is deliberately NOT
integrated here. This module implements the *pattern* with $0, stdlib-only,
local components:

  * An agent loop's small decisions (route / classify / score / is-this-risky /
    is-this-done) are split out of the expensive frontier model into a cheap
    typed decider.
  * The cheap decider returns a TYPED value (Choice / Score / Bool) plus a
    calibrated confidence.
  * Low-confidence decisions escalate to a strong decider (a plug point — no
    model is wired in by default).
  * Risky tool calls pass a three-layer gate: deterministic policy ->
    classifier screen -> human-approval queue. The gate automates SCREENING,
    never CONSENT: it has no execute path, and nothing it queues is ever
    auto-approved.

Stdlib only. No network, no credentials, no paid services.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional


# --------------------------------------------------------------------------
# Typed decisions (cf. Jev's Choice / Score / Noul)
# --------------------------------------------------------------------------

def _check_confidence(c: float) -> float:
    if not 0.0 <= c <= 1.0:
        raise ValueError(f"confidence must be in [0.0, 1.0], got {c}")
    return c


@dataclass
class Decision:
    """Base class: every decision carries a calibrated confidence in [0, 1]."""
    confidence: float
    kind: str = "decision"

    def __post_init__(self):
        _check_confidence(self.confidence)


@dataclass
class Choice(Decision):
    """Pick exactly one value from a defined set of options (Jev: Choice)."""
    value: str = ""
    kind: str = "choice"


@dataclass
class Score(Decision):
    """Place a subject on a defined numeric scale (Jev: Score)."""
    value: float = 0.0
    kind: str = "score"


@dataclass
class Bool(Decision):
    """Is this statement true? (Jev: Noul, expressed here as a bool + confidence.)"""
    value: bool = False
    kind: str = "bool"


@dataclass
class DecisionRequest:
    """A single small decision, stated independently of any model."""
    kind: str                                   # "choice" | "score" | "bool"
    question: str                               # what is being decided
    context: str = ""                           # state the decider may inspect
    options: tuple = ()                         # for kind == "choice"
    scale: tuple = (0.0, 1.0)                   # for kind == "score"
    metadata: dict = field(default_factory=dict)


def _zero_confidence_decision(request: DecisionRequest) -> Decision:
    """A well-formed decision with confidence 0.0 — 'I don't know'.

    Returning this (rather than raising) is how a cheap decider signals the
    Router to escalate.
    """
    if request.kind == "choice":
        return Choice(value=request.options[0] if request.options else "",
                      confidence=0.0)
    if request.kind == "score":
        return Score(value=float(request.scale[0]), confidence=0.0)
    return Bool(value=False, confidence=0.0)


# --------------------------------------------------------------------------
# Deciders
# --------------------------------------------------------------------------

class Decider:
    """Interface: anything that can answer a DecisionRequest with a Decision."""
    name = "decider"

    def decide(self, request: DecisionRequest) -> Decision:
        raise NotImplementedError


class RulesDecider(Decider):
    """Cheap tier: deterministic rules, evaluated in registration order.

    A rule is (kinds, predicate, maker):
      kinds     — set of request kinds the rule applies to (empty = all)
      predicate — fn(request) -> bool
      maker     — fn(request) -> Decision

    If no rule matches, returns a zero-confidence decision, which the Router
    treats as 'escalate'. Deterministic rules are the honest $0 stand-in for
    a fast-decision model: same contract (typed value + confidence), no API.
    """
    name = "rules"

    def __init__(self):
        self._rules = []

    def add_rule(self, predicate, maker, kinds=()):
        self._rules.append((set(kinds), predicate, maker))
        return self

    # -- convenience rule builders ----------------------------------------

    def add_keyword_choice_rule(self, keyword: str, choice_value: str,
                                confidence: float = 0.95):
        """If `keyword` appears in the request text, choose `choice_value`."""
        kw = keyword.lower()
        return self.add_rule(
            lambda r: kw in (r.question + " " + r.context).lower(),
            lambda r: Choice(value=choice_value, confidence=confidence),
            kinds={"choice"},
        )

    def add_flag_bool_rule(self, keyword: str, value: bool = True,
                           confidence: float = 0.95):
        """If `keyword` appears in the request text, answer Bool(value)."""
        kw = keyword.lower()
        return self.add_rule(
            lambda r: kw in (r.question + " " + r.context).lower(),
            lambda r: Bool(value=value, confidence=confidence),
            kinds={"bool"},
        )

    def decide(self, request: DecisionRequest) -> Decision:
        for kinds, predicate, maker in self._rules:
            if kinds and request.kind not in kinds:
                continue
            if predicate(request):
                return maker(request)
        return _zero_confidence_decision(request)


class StrongDecider(Decider):
    """Strong tier: the plug point for a real frontier model.

    Deliberately unimplemented. Subclass this (or use CallableStrongDecider)
    to wire in a model later — e.g. structured outputs from a fleet model, or
    Jev itself if the founder ever approves the paid lane. Nothing in this
    module calls a model.
    """
    name = "strong(unconfigured)"

    def decide(self, request: DecisionRequest) -> Decision:
        raise NotImplementedError(
            "StrongDecider is a plug point: subclass it or wrap a callable "
            "with CallableStrongDecider to connect a real model."
        )


class CallableStrongDecider(StrongDecider):
    """Adapt any fn(request) -> Decision into a StrongDecider."""

    def __init__(self, fn: Callable[[DecisionRequest], Decision],
                 name: str = "strong(callable)"):
        self._fn = fn
        self.name = name

    def decide(self, request: DecisionRequest) -> Decision:
        return self._fn(request)


# --------------------------------------------------------------------------
# Router: cheap first, escalate on low confidence (cf. ModelRouterMiddleware
# + the verified 'cheap filter in front of a frontier model' result)
# --------------------------------------------------------------------------

@dataclass
class RoutedDecision:
    decision: Decision
    source: str                    # "cheap" | "strong"
    escalated: bool
    cheap_decision: Optional[Decision] = None
    escalation_unavailable: bool = False   # wanted to escalate, no strong tier


class Router:
    """Send each decision to the cheap decider; escalate below threshold.

    Every decision (and escalation) is logged in memory and, if log_path is
    given, appended as JSON lines — the audit trail the harness needs to tune
    thresholds and rules later.
    """

    def __init__(self, cheap: Decider, strong: Optional[Decider] = None,
                 threshold: float = 0.8, log_path: Optional[str] = None):
        self.cheap = cheap
        self.strong = strong
        self.threshold = threshold
        self.log_path = log_path
        self.log: list = []

    def decide(self, request: DecisionRequest) -> RoutedDecision:
        cheap_decision = self.cheap.decide(request)
        if cheap_decision.confidence >= self.threshold:
            result = RoutedDecision(decision=cheap_decision, source="cheap",
                                    escalated=False,
                                    cheap_decision=cheap_decision)
        elif self.strong is not None:
            strong_decision = self.strong.decide(request)
            result = RoutedDecision(decision=strong_decision, source="strong",
                                    escalated=True,
                                    cheap_decision=cheap_decision)
        else:
            result = RoutedDecision(decision=cheap_decision, source="cheap",
                                    escalated=False,
                                    cheap_decision=cheap_decision,
                                    escalation_unavailable=True)
        self._record(request, result)
        return result

    def _record(self, request: DecisionRequest, result: RoutedDecision):
        entry = {
            "ts": time.time(),
            "kind": request.kind,
            "question": request.question,
            "cheap_confidence": result.cheap_decision.confidence
                if result.cheap_decision else None,
            "final_confidence": result.decision.confidence,
            "final_value": getattr(result.decision, "value", None),
            "source": result.source,
            "escalated": result.escalated,
            "escalation_unavailable": result.escalation_unavailable,
            "threshold": self.threshold,
        }
        self.log.append(entry)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")


# --------------------------------------------------------------------------
# ToolGate: deterministic policy -> classifier screen -> human-approval queue
# (cf. AutoModeMiddleware, with the layer the middleware omits: consent stays
# human. The gate FAILS CLOSED and never executes anything.)
# --------------------------------------------------------------------------

@dataclass
class ToolCall:
    tool: str
    args: dict = field(default_factory=dict)
    context: str = ""


@dataclass
class QueueEntry:
    id: str
    call: ToolCall
    reason: str
    status: str = "pending"          # pending | approved | rejected
    created: float = field(default_factory=time.time)


@dataclass
class GateResult:
    status: str                      # "allowed" | "denied" | "queued"
    reason: str
    queue_id: Optional[str] = None
    screen: Optional[RoutedDecision] = None

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"


class ToolGate:
    """Screen a proposed tool call before anything executes it.

    Layer 1 — deterministic policy: explicit allow/deny. Deny wins.
    Layer 2 — classifier screen: grey-zone calls are put to the Router as a
              Bool decision ('is this call safe to execute?'). Only a
              confident True passes.
    Layer 3 — human-approval queue: everything else waits for a human.
              approve()/reject() only change the queue record; a human (or a
              human-approved runner outside this module) decides what happens
              next. The gate itself has no execute path by design.
    """

    def __init__(self, screen_router: Optional[Router] = None,
                 allow_tools=(), deny_tools=(), deny_arg_patterns=(),
                 queue_path: Optional[str] = None):
        self.allow_tools = set(allow_tools)
        self.deny_tools = set(deny_tools)
        # deny_arg_patterns: iterable of (tool_name_or_None, regex_str)
        self.deny_arg_patterns = [(t, re.compile(p))
                                  for t, p in deny_arg_patterns]
        self.screen_router = screen_router
        self.queue_path = queue_path
        self.queue: list = []

    # -- layer 1 -----------------------------------------------------------

    def _policy(self, call: ToolCall) -> str:
        if call.tool in self.deny_tools:
            return "deny"
        args_blob = json.dumps(call.args, default=str)
        for tool_name, pattern in self.deny_arg_patterns:
            if tool_name is not None and call.tool != tool_name:
                continue
            if pattern.search(args_blob):
                return "deny"
        if call.tool in self.allow_tools:
            return "allow"
        return "grey"

    # -- main entry ---------------------------------------------------------

    def check(self, call: ToolCall) -> GateResult:
        verdict = self._policy(call)
        if verdict == "deny":
            return GateResult(status="denied",
                              reason=f"deterministic policy denies '{call.tool}'")
        if verdict == "allow":
            return GateResult(status="allowed",
                              reason=f"'{call.tool}' is allow-listed by policy")

        # Grey zone -> layer 2, classifier screen.
        if self.screen_router is not None:
            request = DecisionRequest(
                kind="bool",
                question="Is this tool call safe to execute without human review?",
                context=f"tool={call.tool} args={json.dumps(call.args, default=str)} "
                        f"{call.context}",
            )
            screened = self.screen_router.decide(request)
            d = screened.decision
            if isinstance(d, Bool) and d.value and \
                    d.confidence >= self.screen_router.threshold:
                return GateResult(
                    status="allowed",
                    reason=f"classifier screen passed '{call.tool}' "
                           f"(confidence {d.confidence:.2f})",
                    screen=screened)
            reason = (f"classifier screen did not confidently clear "
                      f"'{call.tool}' (value={getattr(d, 'value', None)}, "
                      f"confidence={d.confidence:.2f})")
            return self._enqueue(call, reason, screen=screened)

        return self._enqueue(call, f"'{call.tool}' is not covered by policy "
                                   f"and no classifier screen is configured")

    # -- layer 3 ------------------------------------------------------------

    def _enqueue(self, call: ToolCall, reason: str,
                 screen: Optional[RoutedDecision] = None) -> GateResult:
        entry = QueueEntry(id=uuid.uuid4().hex[:12], call=call, reason=reason)
        self.queue.append(entry)
        if self.queue_path:
            with open(self.queue_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "event": "queued",
                    "id": entry.id,
                    "tool": call.tool,
                    "args": call.args,
                    "reason": reason,
                    "ts": entry.created,
                }) + "\n")
        return GateResult(status="queued", reason=reason,
                          queue_id=entry.id, screen=screen)

    def pending(self) -> list:
        return [e for e in self.queue if e.status == "pending"]

    def approve(self, entry_id: str) -> QueueEntry:
        """Record a human's approval. Does NOT execute the call — ever."""
        return self._resolve(entry_id, "approved")

    def reject(self, entry_id: str) -> QueueEntry:
        return self._resolve(entry_id, "rejected")

    def _resolve(self, entry_id: str, status: str) -> QueueEntry:
        for entry in self.queue:
            if entry.id == entry_id:
                entry.status = status
                if self.queue_path:
                    with open(self.queue_path, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps({
                            "event": status, "id": entry.id,
                            "ts": time.time(),
                        }) + "\n")
                return entry
        raise KeyError(f"no queue entry {entry_id}")
