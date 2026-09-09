# Milestone 4 — Decisions, Empirical Findings, and What Remains Unproven

Milestone 4 is an integration-validation milestone: prove the production
adapter can talk to a real LocalAI without weakening any Milestone 1–3
guarantee. This document records what was actually measured, and — just as
importantly — what was **not**, because no live LocalAI was reachable from
the environment this work was done in.

## 1. The blocking finding, stated first

**No live LocalAI instance was available, and one could not be created here.**
This was established by measurement, not assumption:

| Check | Result |
|---|---|
| `curl http://127.0.0.1:{8080,8081,1234,3000}/readyz` | all connection failures (HTTP code `000`) |
| `docker info` | `dial unix /var/run/docker.sock: no such file` — no daemon, so the container path is closed |
| `find / -name '*.gguf'` | nothing — no model weights anywhere |
| `env | grep LOCALAI` | unset — no endpoint, model, or credential configured |
| built `local-ai` binary | absent |

The three ways to obtain a live instance were each closed: the container path
needs a Docker daemon that does not exist; the source path needs a full Go +
C++ backend build **and** a GGUF download, and §24 of this milestone
explicitly excludes model downloading; and the external path needs an
endpoint and credential that were never supplied.

Per §26, this is reported rather than worked around. Specifically, **no live
result in this milestone was fabricated against a mock**. The four live
scenarios (§8–§11) are implemented, hardened, and verified to *skip and fail
correctly* — but they have never been observed passing against a real model,
and this document does not claim otherwise.

### What an operator needs to run them

On a machine with LocalAI running (the reference target is the ASUS ROG /
RTX 2070 SUPER described in the specification package):

```
export LOCAL_AGENT_LIVE_MODEL=1
export LOCALAI_MODEL=<a model the instance serves>
export LOCALAI_BASE_URL=http://127.0.0.1:8080   # or LOCALAI_ADDRESS=:8080
export LOCALAI_API_KEY=<key>                     # only if the instance requires one
uv run pytest -m live -q
```

## 2. The gate: skip versus fail

The milestone's mandatory distinction is now implemented and, more usefully,
**verified in both directions**:

| Condition | Behaviour | Verified |
|---|---|---|
| gate absent | SKIP, exit 0 | `5 skipped`, and `pytest -m "not live"` passes offline |
| gate present, `LOCALAI_MODEL` unset | FAIL with an actionable message | observed |
| gate present, service unreachable | FAIL with `ModelTransportError` | observed against port 9 |

This matters because the failure mode it prevents is silent: an operator who
sets the gate, sees green, and concludes the live path worked — when in fact
every test skipped. `tests/test_live_boundary.py` runs pytest in a subprocess
under each condition, so a future refactor that collapses the gate back into
a blanket `skipif` fails the build.

A subtlety worth recording: `pytest.fail()` was originally raised inside the
`except LiveConfigurationError` handler, which chained the exception and
printed the operator's message twice behind "another exception occurred". The
message is now raised outside the handler so it appears once, cleanly.

## 3. Configuration conventions, reused not reinvented

Read from the parent repository rather than from generic OpenAI documentation:

* `core/cli/run.go` — `APIKeys` reads `LOCALAI_API_KEY,API_KEY` in that order;
  `Address` reads `LOCALAI_ADDRESS,ADDRESS`, default `":8080"`.
* `core/http/auth/features.go` — `POST /v1/chat/completions` under `FeatureChat`.
* `core/http/middleware/request.go` — `Authorization: Bearer <key>`.

The live support module follows that precedence exactly. One addition was
unavoidable: `LOCALAI_ADDRESS` is a *bind* address, so `":8080"` means "all
interfaces" to the server and is not dialable by a client. `LOCALAI_BASE_URL`
is therefore honoured first, and a bare `":8080"` is translated to
`http://127.0.0.1:8080` rather than guessed at. Four address shapes are tested.

**Environment reading lives in `tests/live_support.py`, not in the package.**
`src/local_agent/` reads no environment variable at all, and
`test_production_source_reads_no_environment_variable` enforces it. Two
reasons: configuration stays explicit (wiring constructs it; nothing is picked
up ambiently), and `os` stays out of the production import allowlist. A
deployment cannot be silently reconfigured by a variable nobody declared.

## 4. What was proven without a live model

Several requirements are genuinely verifiable offline, and were:

**The HTTP client does not retry.** §12 requires that a client-side retry be
eliminated rather than compensated for. This is now a *measured* fact rather
than an assumption about `urllib`'s internals: the loopback test server counts
requests per path, and a 401, 404, 500, 503, and timeout each produce exactly
one request. The end-to-end test goes further — the real controller, real
adapter, and real transport over a real socket produce exactly three HTTP
requests for a three-attempt budget.

**A failing status triggers no discovery or substitution.** A 404 leaves the
set of requested paths at exactly `{"/404"}` — the client does not probe
alternatives. Across a 401 then a 404 then a success, every request names the
configured model, and a response that *claims* to be a different model does
not change what is sent next.

**The model cannot influence the endpoint.** Across valid, hostile, and
malformed responses, every subsequent request path is the module constant.

**TLS is never weakened.** A scan covers production source *and tests* for
`verify=False`, `_create_unverified_context`, `CERT_NONE`,
`check_hostname = False`, `_create_default_https_context`, and
`PYTHONHTTPSVERIFY`/CA-bundle environment manipulation. Tests are included
deliberately: a live test that failed against a self-signed certificate would
be trivially "fixed" by disabling verification, and that is a security
downgrade hidden in a test file. The project has no custom-CA support, so a
self-signed LocalAI is a documented limitation, not something to bypass.

**The boundary checks themselves work.** Two adversarial tests poison a copy
of `controller.py` with a network import and a copy of `policy.py` with a
filesystem import, and assert the same predicates the real tests use reject
them — and that the unmodified originals pass. A boundary assertion that could
never fail proves nothing.

## 5. The live diagnostic is structural only

`LiveDiagnostic` records shape, never content: which channels carried
something, whether the structured output parsed, the proposed tool name, the
normalized error code, the controller's state trace, and the transport call
count. It has no field capable of holding model text, a credential, a URL
path, or a filesystem path, and a test asserts that. `endpoint_shape` is
deliberately scheme-plus-authority only, so printing it from a live run cannot
disclose a path — and `ModelServiceConfig` already refuses a URL with embedded
credentials, so it cannot disclose one of those either.

This exists because §14 permits recording sanitized structural information
from a live run while forbidding live output from entering the deterministic
fingerprints. Those remain entirely scripted:
`test_invariant_deterministic_replay_never_touches_live_inference` asserts
`test_determinism.py` imports no `HttpModelTransport` and reads no environment.

## 6. Live CI: deliberately not created

§16 says to stop and report if there is insufficient information to construct
a live workflow safely. There is. Missing, and not inferable:

* which host the LocalAI instance runs on and whether a GitHub runner can
  reach it (self-hosted? tunnelled? not reachable at all?);
* which model identifier that instance serves;
* whether a credential is required, and if so how it should be provisioned as
  a repository secret and which secret name to read;
* whether the runner has the GPU and disk the target model needs;
* what the intended failure policy is — a live workflow that fails when the
  operator's machine is off would be noise, not signal.

No workflow was added and the existing CI is untouched. PR mergeability does
not depend on live inference, and `test_invariant_normal_ci_does_not_require_localai`
asserts the workflow names no live gate, model, or endpoint.

## 7. Scope discipline

Nothing from §24's exclusion list was implemented. In particular the milestone
was not used as cover for streaming, model downloading, fallback, routing, or
sandboxing. The only production-adjacent change is configuration: one pytest
marker registration in `pyproject.toml`. `uv.lock` is unchanged and no
dependency was added, upgraded, or removed.

## 8. What remains unproven

Stated plainly, because "the tests pass" and "this works against a real model"
are different claims:

* **No live LocalAI exchange has been observed.** The adapter's wire contract
  is verified against LocalAI's *source-derived* schemas (`core/schema/message.go`,
  `core/schema/openai.go`) and against a loopback server that reproduces those
  shapes — not against a running instance.
* **Tool-calling support is model-dependent and unverified.** Whether a given
  GGUF model served by LocalAI actually emits `tool_calls` rather than prose
  depends on the model and its template. If it emits prose, the adapter fails
  closed and the controller reports `TOOL_CALL_MALFORMED` — correct behaviour,
  but it means the live tool-proposal test may exercise the failure path rather
  than the success path on some models. The test asserts controller behaviour
  on both branches for exactly this reason.
* **LocalAI version drift is untested against a real binary.** The external
  response schemas use `extra="ignore"`, so additive envelope changes are
  tolerated by construction, and a test asserts that. Changes to the fields the
  adapter actually reads — `choices[].message.{content,reasoning,tool_calls}` —
  would break it, and would surface as `model_response_schema_invalid` rather
  than silent misbehaviour.
* **Self-signed TLS is unsupported.** There is no custom-CA configuration. An
  instance behind a self-signed certificate will fail verification, and that is
  a configuration requirement to solve at deployment, not in this code.

The success condition for this milestone was never "the model works". It was
that an unpredictable external model can be connected while the controller
remains the same governed state machine. The connecting half is implemented
and hardened; the *observing* half awaits a machine with LocalAI on it.
