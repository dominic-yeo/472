# DVLA Attack Surface Analysis

Target: Damn Vulnerable LLM Agent (this repo), running at `http://localhost:8501/`.
Schema: [`../schema/L1_schema.yaml`](../schema/L1_schema.yaml) (interaction-level)
and [`../schema/L2_schema.yaml`](../schema/L2_schema.yaml) (semantic/stateful),
records in [`L1_interactions.yaml`](L1_interactions.yaml) and
[`L2_operations.yaml`](L2_operations.yaml).

## Methodology

1. **Source review**: `main.py`, `tools.py`, `transaction_db.py`, `utils.py`,
   `llm-config.yaml`, `config.toml`, `Dockerfile`, `requirements.txt`.
2. **Black-box HTTP recon** against the live server: enumerated Streamlit's
   real vs. SPA-fallback routes, response headers, and static asset handling.
3. **Live WebSocket protocol probing** of `/_stcore/stream` using Streamlit's
   own compiled protobufs (the app's frontend protocol) to test Origin/CSRF
   handling directly.
4. **Live end-to-end exploitation** of both documented CTF flags, run against
   the actual deployed backend (local Ollama `llama3.1:8b`) by invoking the
   identical LangChain `AgentExecutor` + tool code `main.py` wires to the
   WebSocket, in-process. Full transcripts are captured in
   [`L2_operations.yaml`](L2_operations.yaml).

**Limitation, stated plainly**: a scripted (non-browser) WebSocket client
completes the `/_stcore/stream` handshake (HTTP 101) but received zero
ForwardMsg frames in testing, despite server-side Origin validation
provably firing (confirmed by inducing a 400 with a malformed duplicate
Origin header). The likely cause is a missing piece of the browser's exact
post-handshake sequence (subprotocol negotiation / initial client_state) that
wasn't fully reverse-engineered within this engagement. Rather than leave the
two live exploits unverified, they were instead driven through the identical
in-process code path end to end against the real local LLM and the real
SQLite database — dispositive for "does the payload work against this app's
actual logic," slightly short of "captured on the wire on port 8501." See
`web.ws.stream` in `L1_interactions.yaml` for the full note.

## Architecture in one paragraph

DVLA is a single Streamlit page (`main.py`). There is no REST API, no
authentication, and no per-user session concept — "the current user" is a
hardcoded constant (`userId=1`, MartyMcFly) returned by a `GetCurrentUser`
LangChain tool that ignores its own input. A `ConversationalChatAgent`
(ReAct-style) has two tools: `GetCurrentUser` and `GetUserTransactions`. The
only thing stopping the agent from querying any other user's transactions is
one sentence of the system prompt (`main.py:21`) — there is no code-level
enforcement anywhere. `GetUserTransactions` also builds its SQL query with an
f-string, not parameter binding, so whatever string the LLM decides to pass
as `userId` goes straight into `SELECT * FROM Transactions WHERE userId =
'<here>'`.

## Findings, ranked

1. **Broken object-level access control via prompt injection**
   (`chat.system_message_override_idor`) — a single chat message containing a
   fake `(#system)` directive gets the agent to abandon `GetCurrentUser()`
   entirely and query `userId=2` on request. Reproduced live in one turn.
   CWE-1390 / CWE-863, OWASP LLM01:2025.

2. **SQL injection via ReAct-transcript injection**
   (`chat.union_sqli_password_exfil`) — a chat message containing a forged
   prior `Observation`/`Thought` biases the agent's next real tool call to
   use a UNION-based payload as `userId`, dumping every seeded user's
   plaintext password. Reproduced live in one turn. Root cause is
   compounded by the vulnerable tool's own natural-language description
   (`tools.py:43`) spelling out the unparameterized query shape to the LLM.
   CWE-89 / CWE-1390, OWASP LLM01:2025 + LLM02:2025.

3. **Plaintext password storage**, independent of the injection above —
   `Users.password` is stored and returned in cleartext
   (`transaction_db.py:39-43`). CWE-522.

4. **Zero rate limiting / cost controls** — every unauthenticated chat turn
   triggers up to `max_iterations=6` LLM calls; `.gitignore` reserves a
   `rate_limit.db` that no code ever creates. Not exploitable against the
   current local-Ollama config, but a real cost-DoS surface the moment
   `model_name` points at a metered OpenAI model. OWASP LLM10:2025.

5. **No security headers / no CSRF hardening on the one true entry point**
   — `/_stcore/stream` allows WebSocket connections with no `Origin` header
   at all (by Streamlit's own documented design), and the root HTML response
   carries none of CSP/X-Frame-Options/HSTS/etc. Low standalone severity
   given there's no authenticated session to hijack, but worth noting for
   defense-in-depth.

6. **Dead-code SQLi twin** — `TransactionDb.get_user()` has the identical
   f-string injection pattern as the exploited method, but its only caller
   hardcodes the argument and ignores LLM input, so it's currently
   unreachable. Flagged because it would become live the moment anyone
   "fixes" `GetCurrentUser` to actually honor a caller-supplied user id
   without also fixing the query.

## Why this app is unusual for the L1/L2 schema

The schema (built against a much larger, multi-service FastAPI app) expects
many discrete HTTP routes per business operation. DVLA has exactly one real
interactive channel (`/_stcore/stream`) carrying every operation as opaque
widget-state updates, so almost all of the interesting differentiation lives
in L2 (`semantic_operation`, by chat-message content) rather than L1
(`path`/`method`). This is itself a useful structural observation: **a
single-WebSocket, no-REST agentic frontend has no route-level surface to
apply conventional per-endpoint controls (rate limiting, WAF rules, RBAC
middleware) to** — any control has to live inside the agent/tool logic
itself, and here, none does.
