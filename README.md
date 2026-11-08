# HashBound — Tamper-Proof Agent Approvals

**An approval is bound to the hash of the exact payload approved. Change the payload after approval — the approval voids, automatically, with a diff showing exactly what changed.**

AI agents that *execute* — sending, publishing, submitting, spending — need human approval for consequential actions. But a plain "approved ✓" is worthless if the payload can change after the click: approve a message to one recipient, swap the recipient, execute. Nothing in a conventional approval queue notices.

HashBound closes that hole:

1. **Queue time:** every gated action is snapshotted and bound to `SHA-256(tool + args + context)` (canonical JSON, key-order independent).
2. **Approve time:** the queued payload is re-hashed. Any in-place mutation voids the approval (`voided_tamper`) with an approved-vs-attempted field diff.
3. **Execute time:** the separate Executor re-hashes the payload it is about to run and refuses — `DENY — TAMPER` — unless it matches an approved entry's bound hash. An approval can never be spent on a different payload.
4. **No verdict cache, anywhere.** Every verdict is computed fresh for the exact payload in front of the gate. (This rule is a direct response to a real audit finding: a reviewer whose writable verdict cache returned stored accepts verbatim, letting one payload's verdict be replayed onto another.)
5. **Approvals are one-time and short-lived.** Approval mints a one-time execution token, consumed by the first execution — an executed approval can never be replayed, and a token minted for one action is refused on any other. Pending and issued approvals both expire after a configurable TTL (default 300 s) and fail closed to re-queue.
6. **The proposer can never approve their own action.** A second, distinct approver is required; a self-approval attempt is blocked (and the entry stays pending for a real approver).
7. **The receipts ledger is hash-chained.** Every receipt carries the previous receipt's hash, so rewriting or deleting history breaks the chain — and a verifier (`verify_ledger_chain`) detects exactly where.

## How it works

```
Agent proposes action
        │
        ▼
┌──────────────────── HashBound gate (Vultr VM) ────────────────────┐
│ Layer 1  Deterministic policy — 8 action classes, deny wins:      │
│          read ALLOW · local write ALLOW · external send GATE ·    │
│          deploy/publish GATE · spend DENY · delete DENY ·         │
│          secrets DENY · gate self-modification DENY               │
│ Layer 2  Classifier screen (Vultr Serverless Inference) — only a  │
│          confident "safe" clears a grey-zone call; any failure    │
│          fails closed to the queue                                │
│ Layer 3  Human approval queue — hash-bound at queue time,         │
│          hash-verified at approve time                            │
└───────────────────────────────────────────────────────────────────┘
        │ approved + hash still matches
        ▼
Executor (separate from the gate) — re-hashes at run time, then runs
        │
        ▼
Receipts ledger — every verdict, hash, approval, tamper block, and
execution, in order, hash-chained so history can't be quietly
rewritten. If it isn't in the ledger, it didn't happen.
```

The gate itself has **no execute path** — screening is not consent, and consent is not execution. That separation is the product's thesis: *an agent that executes safely is a product; an agent that only chats is a demo.*

## The containment moment

The demo's centrepiece, reproducible from the homepage in one click (`POST /api/tamper-demo`, also covered by tests):

1. An agent queues a send to a legitimate recipient → **QUEUED**, hash-bound.
2. A human approves it honestly → **APPROVED**, hash verified unchanged.
3. The payload's recipient is swapped and execution is attempted → **TAMPER_BLOCKED**, approval void, diff shows `to: approved → attempted`. The swapped payload never executes.

A second containment layer covers hostile inputs: if content the agent read (for example a source page containing an embedded instruction) leads it to propose a secrets access or a destructive delete, those are **DENY classes** — denied deterministically, before any model is consulted, each with a receipt naming the class and rule that fired.

## The approval-layer probe suite

Sandbox attack-probe suites are common; probes against the **approval layer** are not. `probes.py` runs seven attacks against the approval itself, against the real gate and executor, and prints a measured scoreboard:

| Probe | Attacks | Result |
|---|---|---|
| `tamper_after_approval` | swap a payload field after queueing | `tamper_blocked` |
| `replay_executed_approval` | execute the same approval twice | `replay_blocked` — payload ran exactly 1 time |
| `stale_approval` | approve / execute after the TTL lapses | `expired` — both phases fail closed |
| `approval_token_reuse` | spend one action's token on another | `approval_reuse_blocked` |
| `decimal_shift_amount` | execute 100.00 approved as 10000.00 | `tamper_blocked`, diff `amount: 100.00 → 10000.00` |
| `self_approval` | proposer approves their own action | `self_approval_blocked`; a distinct approver still succeeds |
| `ledger_chain_tamper` | rewrite a historical receipt | chain verifies intact; mutation detected |

**Probe scoreboard: 7/7 PASS** (`python3 probes.py`, exit code 0). Every probe is also a unit test in `test_probes.py`.

## Vultr services used

| Service | Role |
|---|---|
| **Vultr Cloud Compute VM** | Hosts the control plane (gate, approval queue, receipts ledger, web UI) and the per-task sandbox |
| **Vultr Serverless Inference** | **All** agent LLM calls: the classifier screen for grey-zone actions and form-field value preparation. OpenAI-compatible endpoint; model pinned from the live `GET /v1/models` catalog at deploy time |
| Docker (on the VM) | Per-task isolated execution: resource caps, empty environment (no credentials inside), destroyed after each task |

There is no other model call in the system. Deterministic verdicts (every ALLOW/DENY/GATE in the demo) never depend on model availability; if inference is unreachable, grey-zone work queues for a human instead of executing — the gate fails closed.

## Run it

```bash
# stdlib only — no pip installs
cp .env.example .env   # add your Vultr Serverless Inference key
set -a; source .env; set +a
python3 app.py         # http://localhost:8080
```

Or with Docker Compose on a Vultr VM: `docker compose up -d`.

Tests (also stdlib only):

```bash
python3 -m unittest discover -v   # 51 tests
# test_hashbound.py        — policy classes + the tamper tests (19)
# test_vultr_inference.py  — inference client, fail-closed behaviour (7)
# test_probes.py           — replay / stale / reuse / self-approval /
#                            decimal-shift / ledger chain (17)
# test_decision_layer_baseline.py — the disclosed baseline gate suite (8)

python3 probes.py                 # approval-layer probe suite: 7/7 PASS
```

## What's in this repo

| File | What it is |
|---|---|
| `hashbound.py` | The differentiator: hash-bound queue, approve-time verification, one-time expiring approvals, proposer≠approver, executor re-check, hash-chained receipts ledger |
| `decision_layer.py` | The baseline decision-layer / ToolGate implementation this builds on (the author's own prior open work, disclosed — see Provenance) |
| `vultr_inference.py` | The only LLM path: Vultr Serverless Inference client (env-configured, fail-closed) |
| `sandbox.py` | Capped per-task execution (empty env, timeout + kill, output hash for the ledger) |
| `app.py` | Web app: propose → verdict → queue → approve → tamper demo → ledger |
| `probes.py` | The approval-layer probe suite: 7 attacks on the approval itself, measured scoreboard |
| `test_*.py` | 51 tests, including the tamper sequence that used to pass silently |

## Who it's for

Any team deploying agents that act in the world — operations fleets, support agents, research agents — whose compliance owner asks the only question that matters: *"Show me exactly what was approved, and prove what ran is what was approved."* HashBound's answer is a hash, a ledger, and a demo where tampering visibly fails.

## Limits, stated plainly

- Docker on one VM is an *isolated sandbox*, not verified containment; the README claims isolation, never proof against a determined sandbox escape.
- SHA-256 proves a payload (or a fetched page) is byte-identical to what was approved/captured — it does not prove the content is true.
- Hackathon scope: single-operator approval queue, no multi-user auth.

## Provenance & licence

Built for the Vultr Agent Rush hackathon (Challenge 1). The gate semantics and the 8-class policy are the author's own prior work, re-implemented and extended here with the hash-binding layer, which is new. MIT licensed — see `LICENSE`.
