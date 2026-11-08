"""
app.py — HashBound web app (stdlib only, no build step).

Run:
    VULTR_INFERENCE_API_KEY=... VULTR_INFERENCE_MODEL=... \
        python3 app.py            # serves on $PORT or 8080

Pages:
    /            the demo: propose an action, watch the verdict,
                 approve from the queue, run the tamper demo
    /ledger      the receipts ledger (every verdict + hash)
    /health      JSON health + inference-configured status

API (JSON):
    POST /api/propose   {tool, args, context}      -> gate verdict (+hash)
    POST /api/approve   {queue_id, attempted?}     -> approved | tamper_blocked
    POST /api/execute   {queue_id, attempted}      -> executed | tamper_blocked
    POST /api/reject    {queue_id}                 -> rejected
    POST /api/tamper-demo {}                       -> the centrepiece,
                                                      scripted end-to-end
    GET  /api/state                                -> queue + ledger + status

All LLM calls go through vultr_inference.VultrInferenceClient — there
is no other model call in this codebase. Deterministic DENY/GATE/ALLOW
verdicts never depend on the model.
"""

from __future__ import annotations

import html
import json
import os

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from decision_layer import ToolCall
from hashbound import Executor, HashBoundGate
from sandbox import run_snippet
from vultr_inference import VultrInferenceClient, make_screen

CLIENT = VultrInferenceClient()
GATE = HashBoundGate(screen=make_screen(CLIENT))
EXECUTOR = Executor(GATE)

# Demo executions are record-only: "executing" a send in the demo
# appends to this outbox instead of touching the real world.
OUTBOX: list = []


def _run_payload(call: ToolCall):
    OUTBOX.append({"tool": call.tool, "args": call.args})
    return f"executed {call.tool} (demo outbox, entry #{len(OUTBOX)})"


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>HashBound — approval you can't tamper with</title>
<style>
body{font-family:system-ui,sans-serif;max-width:880px;margin:2rem auto;padding:0 1rem}
code{background:#f0f0f0;padding:.1em .3em;border-radius:4px}
.card{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
.denied{border-color:#c00}.queued{border-color:#d90}.allowed{border-color:#090}
button{padding:.5rem 1rem;margin:.25rem;cursor:pointer}
pre{white-space:pre-wrap;word-break:break-all}
</style></head><body>
<h1>HashBound</h1>
<p><strong>An approval is bound to the hash of the exact payload approved.</strong>
Change the payload after approval &mdash; the approval voids, automatically,
with a diff showing exactly what changed. There is no verdict cache to steal.</p>
<p>Inference: __INFERENCE__ &middot; <a href="/ledger">receipts ledger</a></p>

<div class="card">
<h2>1 &middot; Propose an action</h2>
<form id="propose">
<label>Tool
<select name="tool">
<option>send_email</option><option>publish_brief</option>
<option>submit_form</option><option>read_file</option>
<option>spend</option><option>delete_file</option>
<option>read_secret</option>
</select></label>
<label>Recipient / target <input name="to" value="lead@example.com" size="28"></label>
<button type="submit">Propose</button>
</form>
<pre id="propose-out"></pre>
</div>

<div class="card">
<h2>2 &middot; The tamper demo (the centrepiece)</h2>
<p>One click: queue a send, approve it honestly, then try to spend that
approval on a payload whose recipient was swapped. Watch it block.</p>
<button id="tamper">Run tamper demo</button>
<pre id="tamper-out"></pre>
</div>

<div class="card">
<h2>3 &middot; Approval queue</h2>
<div id="queue"></div>
<button onclick="refresh()">Refresh queue</button>
</div>

<script>
async function post(path, body){
  const r = await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body||{})});
  return r.json();
}
document.getElementById('propose').addEventListener('submit', async e=>{
  e.preventDefault();
  const f = new FormData(e.target);
  const out = await post('/api/propose',{tool:f.get('tool'),
    args:{to:f.get('to'),subject:'Sourced brief',body:'Attached.'},context:'demo'});
  document.getElementById('propose-out').textContent = JSON.stringify(out,null,2);
  refresh();
});
document.getElementById('tamper').addEventListener('click', async ()=>{
  const out = await post('/api/tamper-demo',{});
  document.getElementById('tamper-out').textContent = JSON.stringify(out,null,2);
  refresh();
});
async function act(path, id){
  const out = await post(path,{queue_id:id});
  alert(JSON.stringify(out,null,2)); refresh();
}
async function refresh(){
  const s = await (await fetch('/api/state')).json();
  document.getElementById('queue').innerHTML = s.pending.length
    ? s.pending.map(e=>'<div class="card queued"><code>'+e.id+'</code> '+e.tool+
      ' &mdash; hash <code>'+e.bound_hash.slice(0,16)+'…</code><br>'+
      '<button onclick="act(\\'/api/approve\\',\\''+e.id+'\\')">Approve (hash-verified)</button>'+
      '<button onclick="act(\\'/api/reject\\',\\''+e.id+'\\')">Reject</button></div>').join('')
    : '<p>No pending actions.</p>';
}
refresh();
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode())
        except Exception:
            return {}

    # -- GET -----------------------------------------------------------------

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, json.dumps(
                {"status": "ok", "inference": CLIENT.status(),
                 "pending": len(GATE.pending()),
                 "ledger_events": len(GATE.ledger)}))
        if self.path == "/api/state":
            return self._send(200, json.dumps({
                "inference": CLIENT.status(),
                "pending": [{"id": e.id, "tool": e.call.tool,
                             "args": e.call.args,
                             "bound_hash": e.bound_hash,
                             "status": e.status}
                            for e in GATE.pending()],
                "ledger": GATE.ledger[-50:],
                "outbox": OUTBOX,
            }, default=str))
        if self.path == "/ledger":
            rows = "".join(
                f"<tr><td>{html.escape(str(e.get('event')))}</td>"
                f"<td>{html.escape(str(e.get('tool', '')))}</td>"
                f"<td><code>{html.escape(str(e.get('bound_hash', ''))[:20])}…</code></td>"
                f"<td>{html.escape(str(e.get('status', '')))}</td></tr>"
                for e in GATE.ledger)
            return self._send(200, "<!doctype html><title>Ledger</title>"
                              "<h1>Receipts ledger</h1><table>" + rows +
                              "</table><p><a href='/'>back</a></p>",
                              "text/html; charset=utf-8")
        if self.path == "/sandbox-check":
            rec = run_snippet("print('sandbox alive'); "
                              "import os; print(sorted(os.environ))")
            return self._send(200, json.dumps(rec))
        status = ("configured, model " + CLIENT.model) if \
            CLIENT.is_configured() else \
            "NOT configured — deterministic gate only, grey zone queues"
        return self._send(200, PAGE.replace("__INFERENCE__", status),
                          "text/html; charset=utf-8")

    # -- POST ------------------------------------------------------------------

    def do_POST(self):
        body = self._json_body()
        if self.path == "/api/propose":
            call = ToolCall(tool=str(body.get("tool", "")),
                            args=body.get("args") or {},
                            context=str(body.get("context", "")))
            r = GATE.check(call)
            return self._send(200, json.dumps(
                {"status": r.status, "reason": r.reason,
                 "queue_id": r.queue_id, "bound_hash": r.bound_hash},
                default=str))
        if self.path == "/api/approve":
            att = body.get("attempted")
            attempted = ToolCall(tool=att["tool"], args=att.get("args") or {},
                                 context=att.get("context", "")) if att else None
            r = GATE.approve(str(body.get("queue_id", "")), attempted=attempted)
            return self._send(200, json.dumps(
                {"status": r.status, "reason": r.reason,
                 "bound_hash": r.bound_hash,
                 "attempted_hash": r.attempted_hash,
                 "tamper_diff": r.tamper_diff}, default=str))
        if self.path == "/api/execute":
            att = body.get("attempted") or {}
            attempted = ToolCall(tool=att.get("tool", ""),
                                 args=att.get("args") or {},
                                 context=att.get("context", ""))
            r = EXECUTOR.execute(str(body.get("queue_id", "")), attempted,
                                 run=_run_payload)
            return self._send(200, json.dumps(
                {"status": r.status, "reason": r.reason,
                 "bound_hash": r.bound_hash,
                 "attempted_hash": r.attempted_hash,
                 "tamper_diff": r.tamper_diff}, default=str))
        if self.path == "/api/reject":
            r = GATE.reject(str(body.get("queue_id", "")))
            return self._send(200, json.dumps(
                {"status": r.status, "reason": r.reason}, default=str))
        if self.path == "/api/tamper-demo":
            honest = ToolCall(tool="send_email",
                              args={"to": "lead@example.com",
                                    "subject": "Sourced brief",
                                    "body": "Attached."},
                              context="tamper demo")
            queued = GATE.check(honest)
            approved = GATE.approve(queued.queue_id, attempted=honest)
            evil = ToolCall(tool="send_email",
                            args={"to": "attacker@example.com",
                                  "subject": "Sourced brief",
                                  "body": "Attached."},
                            context="tamper demo")
            blocked = EXECUTOR.execute(queued.queue_id, evil,
                                       run=_run_payload)
            return self._send(200, json.dumps({
                "step1_queued": queued.status,
                "bound_hash": queued.bound_hash,
                "step2_honest_approve": approved.status,
                "step3_tampered_execute": blocked.status,
                "reason": blocked.reason,
                "tamper_diff": blocked.tamper_diff,
                "outbox_size": len(OUTBOX),
                "verdict": ("BLOCKED — the swapped payload never "
                            "executed" if blocked.status ==
                            "tamper_blocked" else "UNEXPECTED"),
            }, default=str))
        return self._send(404, json.dumps({"error": "not found"}))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"HashBound on :{port} — inference "
          f"{'configured' if CLIENT.is_configured() else 'NOT configured'}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
