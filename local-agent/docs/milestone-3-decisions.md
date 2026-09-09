# Milestone 3 — Decisions, Conflicts, and Limitations

Milestone 3 replaces the scripted model seam with a production adapter that
talks to LocalAI. The adapter gains no authority: it transports untrusted
output, and every existing gate still decides what happens to it.

## 1. Which LocalAI interface, and why

Inspection of the parent repository found one interface that satisfies the
existing `ModelAdapter` contract without inventing anything:

* `POST /v1/chat/completions` — registered in `core/http/auth/features.go`
  under `FeatureChat`, OpenAI-compatible.
* Authentication is `Authorization: Bearer <key>`, read in
  `core/http/middleware/request.go`; keys come from `LOCALAI_API_KEY` /
  `API_KEY` (`core/cli/run.go`).
* The service binds `LOCALAI_ADDRESS`, default `:8080`.
* Health endpoints `/healthz` and `/readyz` exist (`core/http/routes/health.go`)
  but are not used: a health probe would be a second network call per attempt
  with no bearing on whether *this* request succeeds, and the transport's
  normalized failure already says the service is unreachable.

There is no existing Python client to LocalAI in the repository, no shared
Python HTTP configuration, and no Python endpoint convention — the parent
project is Go, and its Python backends speak gRPC to LocalAI rather than HTTP
from it. So there was nothing to reuse at the client layer, and the narrowest
interface that satisfies the contract is the chat-completions endpoint.

**Alternatives rejected.** Ollama and Anthropic-shaped endpoints also exist in
`core/schema/`, but the OpenAI one is the canonical surface, is the one the
auth layer treats as the primary chat feature, and is the only one whose
response carries the three separate channels this architecture needs. The gRPC
backend interface was rejected outright: it is LocalAI's *internal* boundary to
model runtimes, coupling to it would mean adding a gRPC dependency and
reaching past the service's own API.

## 2. The three-channel mapping

This is the part that makes the security property real against a live model.
LocalAI's `Message` (`core/schema/message.go`) has three separate fields, and
they map exactly onto the channels Milestone 1 defined:

| LocalAI wire field | `ModelResponse` channel | Parsed? |
|---|---|---|
| `message.reasoning` | `reasoning` | never |
| `message.content` | `narrative` | never |
| `message.tool_calls` | `structured_output` | yes, by `parse_candidate` |

Milestone 1 described `structured_output` as "the raw text of whatever
structured-generation facility the runtime exposes (e.g. a function-calling
channel)". `tool_calls` is precisely that facility. Prose therefore cannot
become a proposal — not because prose is filtered, but because it arrives on a
field the parser does not read.

**Fail closed, no fallbacks.** If `tool_calls` is absent, empty, ambiguous
(more than one call), or has no function name, `structured_output` is `None`
and the controller reports `TOOL_CALL_MALFORMED`. The adapter never recovers a
missing proposal from narrative, never concatenates reasoning into it, and
never infers a call from prose.

**Why the multi-call case fails rather than picking the first.** Milestone 1
already treats a multi-call payload as malformed rather than choosing among
competing proposals. Silently taking `tool_calls[0]` would mean a model could
append a second, innocuous-looking call and rely on the reader's assumption
about which one ran.

## 3. Not a second parser

The adapter re-shapes `{"function": {"name": N, "arguments": "<json string>"}}`
into the envelope `{"tool": N, "arguments": {...}}` that `parse_candidate`
already consumes. That is channel normalization, not parsing authority: the
adapter makes no acceptance decision, and every rejection still comes from the
one parser.

When the model's `arguments` string is not valid JSON, the adapter **forwards
that raw text unchanged** rather than judging it. The controller's parser then
produces `TOOL_CALL_MALFORMED` exactly as it would for any other malformed
candidate. Duplicating the malformed-JSON verdict in the adapter is how two
parsers with subtly different semantics come into existence.

**An approach that was rejected.** Building the envelope by string
interpolation — `'{"tool": %s, "arguments": %s}'` — would have avoided parsing
the arguments at all. It is also an injection primitive: model-controlled text
spliced into JSON can introduce a duplicate `"tool"` key, and `json.loads`
keeps the last occurrence. Parse-then-reserialize has no such property.

## 4. Conflict: the retry budget in feedback

**The conflict.** Milestone 1's specification (spec 03 §6) shows the feedback
sent to the model containing `attempt`, `max_attempts`, and
`retry_budget_remaining` — and `ToolFeedback` carries them. Milestone 3 §12 and
§21 state that the retry budget must never appear in a model request.

**Resolution.** `ToolFeedback` is unchanged: Milestone 1's contract still
carries all four fields, the controller still populates them, and the existing
tests still assert on them. What changed is transmission — the adapter projects
the feedback onto the subset the model may see:

```
{type, tool, accepted, error: {code, message, field_errors}}
```

`attempt`, `max_attempts`, `retry_budget_remaining`, and `retryable` are
dropped at the wire. The model still learns exactly what a legitimate repair
needs, and learns nothing about a budget it cannot change anyway. A test
asserts the outgoing payload contains none of those field names.

This satisfies both documents rather than choosing between them, but it is a
genuine divergence from the Milestone 1 worked example and is reported as one.

## 5. Error normalization — no new error codes

Milestone 3 §14 says not to expand the eight-code protocol casually. It was not
expanded. Three adapter exceptions map onto existing codes:

| Exception | Code | Retryable | Reasons |
|---|---|---|---|
| `ModelTransportTimeout` | `EXECUTION_TIMEOUT` | yes | `model_transport_timeout` |
| `ModelTransportError` | `EXECUTION_FAILED` | yes | `model_transport_unreachable`, `model_service_status_<n>`, `model_transport_failed` |
| `ModelResponseInvalid` | `VERIFICATION_FAILED` | yes | `model_response_malformed_json`, `model_response_not_utf8`, `model_response_not_an_object`, `model_response_schema_invalid`, `model_response_no_choices`, `model_response_no_message`, `model_response_too_large`, `model_structured_output_too_large` |

The mapping is not a stretch. `VERIFICATION_FAILED` already means "something
downstream returned a shape we cannot trust", which is exactly what a malformed
completion is. All three are retryable and bounded by the controller's existing
budget, so a dead model service costs three attempts and then terminates at
`RETRY_EXHAUSTED`.

A transport failure that will never succeed on retry — a 401, a misconfigured
endpoint — still consumes the full budget rather than failing fast. That is a
deliberate trade: distinguishing "permanently broken" from "transiently broken"
would mean the adapter classifying service behaviour, and three attempts
against a dead service is bounded and harmless.

## 6. Retry ownership

The adapter and the transport never retry. `urllib` is called exactly once per
`send`, and `send` is called exactly once per `chat`. A transport retrying
three times inside a controller retrying three times would make nine model
calls against a budget of three, invisibly. Tests assert transport call count
equals controller attempt count for both the default budget and a custom one.

## 7. A new state-machine edge: `GENERATE -> FEEDBACK`

With a scripted adapter the model call could not fail. With a real one it can —
the service may time out, be unreachable, or answer unusably — and there is
then no generation to parse. `GENERATE -> FEEDBACK` was added to the transition
table for exactly that case.

This is the same shape as Milestone 2's `EXECUTE -> FEEDBACK` and grants
nothing: FEEDBACK is the universal rejection path, and the exhaustive
169-pair transition test picks up the new edge automatically. `EXECUTE` is
still reachable only from `POLICY_CHECK`.

## 8. Configuration authority

`ModelServiceConfig` is frozen and validated at construction. The model cannot
supply a base URL, host, port, endpoint, credential, timeout, ceiling,
temperature, or token limit — none of these are reachable from model output by
any code path.

**URL validation** is a strict whitelist grammar, hand-written rather than
delegated to `urllib.parse`. Two reasons: keeping `urllib` confined to one
module makes the network grant a one-line fact the architecture test asserts;
and this boundary wants over-rejection, where a permissive parser wants the
opposite. It rejects a missing scheme, any scheme but `http`/`https` (no
`file:`, `ftp:`, `data:`, `gopher:`), credentials in the authority, an empty or
malformed host, an out-of-range or non-numeric port, whitespace, and query or
fragment components.

**The credential is `repr=False`.** A frozen dataclass's generated `__repr__`
would otherwise print the API key into any log line, exception, or debugger
frame that rendered the config. A test supplies a sentinel and asserts it
appears in neither `repr()` nor `str()`.

**Model timeout is not tool timeout.** `ModelServiceConfig.timeout_seconds`
bounds one HTTP round trip to the model service. `ToolSpec.timeout_seconds`
bounds a tool call. They are separate concerns with separate owners and are
deliberately not shared.

## 9. Response size

The transport reads at most `max_response_bytes + 1` — enough to prove a body
is oversized, never enough to hold one. Peak memory is bounded regardless of
what the service sends. `max_structured_output_bytes` separately bounds the
candidate envelope, so a large narrative is fine while an enormous proposal is
refused. Both are rejections, not truncations, for the same reason as
Milestone 2: a silently shortened payload is indistinguishable from a complete
one.

## 10. Dependency decision — zero new dependencies

`pyproject.toml` and `uv.lock` are unchanged. The transport uses
`urllib.request` from the standard library, and the behaviour it depends on was
verified empirically before the code was written rather than assumed:

* a POST with a JSON body and a Bearer header
* `timeout=` raising `TimeoutError` (not `socket.timeout`, on Python 3.10+)
* `read(n)` returning exactly `n` bytes of an arbitrarily larger body
* `urllib.error.HTTPError` on a non-2xx status, with a readable body
* `urllib.error.URLError` on a refused connection

`urllib` is blocking, so the round trip runs on a worker thread via
`asyncio.to_thread`. That is why `asyncio` rides along in the same module
grant; it is not itself a network capability.

An async HTTP client (`httpx`, `aiohttp`) would have been more idiomatic for a
high-concurrency service. This controller makes one model call per attempt and
awaits it, so the added dependency would buy nothing here and cost a supply
chain entry, a lockfile change, and a new upgrade obligation.

## 11. Architecture boundary

Network access is granted per module, never globally — the same pattern
Milestone 2 established for the filesystem. `transports/http.py` is the only
production module that may import a network library, and
`test_only_the_http_transport_holds_a_network_grant` asserts both that the
grant map contains exactly one holder and that the set of modules actually
importing one is exactly `["http.py"]`, so an ungranted module acquiring
`urllib` fails even if someone forgets to update the map.

Additional structural assertions: the control plane (controller, policy, state
machine, contracts, registry, events, wiring, executors) and the entire model
layer except the transport cannot import a network library; the model layer
cannot import a filesystem library; the transport cannot import the
controller's authority modules; and no model-layer module references
`RunContext`, `ToolRegistry`, `ToolSpec`, `Run`, `State`, or `TRANSITIONS`.

## 12. Deterministic testing strategy

The deterministic suite never opens a socket to a model service. Model-adapter
tests drive the production `LocalAIModelAdapter` over an in-process
`ScriptedTransport` whose scripted outcomes include responses *and* exceptions,
so a timeout or a connection failure is expressed without a network.

`tests/test_http_transport.py` is the exception, and deliberately so: the
module holding the network grant would otherwise have no coverage at all. It
runs against a standard-library HTTP server on `127.0.0.1` — no LocalAI, no
credentials, no downloads, no external network — and verifies the real timeout,
the real bounded read against a 300 KB body, real HTTP-500 and
connection-refused handling, and that no failure carries the host or the key.

**Request determinism.** The payload is serialized with sorted keys and compact
separators and contains no timestamp, UUID, hostname, or process id, so
identical controller input produces byte-identical bytes. The exact request is
therefore part of the replay fingerprint rather than something excluded from
it.

**What determinism means here.** Ten model scenarios each run 100 times against
the same scripted transport and produce exactly one fingerprint apiece, and the
ten fingerprints are mutually distinct. The claim this supports is *controller
determinism under controlled model responses and controlled transport
fixtures*. It is not a claim that the model is deterministic — a real model is
probabilistic, its output is not reproducible, and nothing in this project tries
to make it so. The determinism lives in the control plane; the nondeterminism
stays on the far side of the adapter, where it is treated as untrusted data.

## 13. Live smoke test policy

`test_live_model_service_smoke` is skipped unless `LOCAL_AGENT_LIVE_MODEL` is
set, and additionally needs `LOCALAI_MODEL` (plus optional `LOCALAI_BASE_URL`
and `LOCALAI_API_KEY`). It is not in the CI path, requires no secrets in CI,
and cannot fail normal CI when no model server is running.

When it does run it verifies the adapter *contract* only: that a response can
be obtained and mapped to the three channels. It does not assert on generated
content, does not execute the returned proposal, and does not log the response
— a probabilistic model's output is not an acceptance criterion.

## 14. Known limitations

* **The model service is trusted to the extent that it is reachable.** TLS
  verification is Python's default and is not disabled anywhere, but a
  compromised or spoofed model service can return anything. That is precisely
  why its response is schema-validated, size-bounded, and treated as untrusted
  — but a hostile service can still waste the retry budget and can still
  propose calls, which the gates then judge on their merits.
* **No streaming.** `stream: false` is always sent. Streaming would mean
  incremental parsing of a partially-received structured channel, which is a
  materially different security problem.
* **No health probe, no model routing, no fallback.** A configured service that
  is down produces a normalized failure. There is deliberately no automatic
  switch to another endpoint or model: a silent fallback is a hidden change of
  the thing being trusted.
* **The transport blocks a worker thread** for the duration of a request. Fine
  for one call per attempt; it would need revisiting for concurrent runs.
* **Prompt-injection defence is structural, not semantic.** Nothing here
  detects a malicious instruction. The defence is that instructions arrive on
  channels the parser never reads, and that a proposal from the channel it does
  read still has to pass validation, authorization, and policy. A model can
  always propose something harmful; it cannot make the controller accept it.
