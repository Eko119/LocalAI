# Local AI Agent — Deterministic Controller, Filesystem, Model Adapter, Durable State

A deterministic control plane that treats an LLM as an untrusted proposal
engine. The model may suggest a tool call; nothing else about the model's
output has any authority.

    MODEL PROPOSES · CONTROLLER DECIDES · POLICY AUTHORIZES
    EXECUTOR ACTS  · VERIFIER CHECKS   · PERSISTENCE RECORDS

Milestone 1 proved, with executable tests, that a model producing arbitrary
malformed or hostile output cannot obtain unauthorized execution authority.
Milestone 2 gives the controller its first real external capability — read-only
filesystem access — without giving the model any filesystem authority at all:
it names an abstract root and a relative path, and never learns where either
one physically is. Milestone 5 makes controller state survive a crash without
making the durable store an authority: a journal records what the controller
decided, and everything read back is re-validated against live invariants
before it is believed.

## The pipeline

Every proposal walks the same path, and every stage can end the run:

    RAW MODEL OUTPUT
      -> PARSE            only the approved structured channel is read
      -> CANDIDATE        a typed envelope, nothing more
      -> SCHEMA VALIDATE  the tool's own Pydantic schema
      -> AUTHORIZE        does this run hold the grants?
      -> POLICY           do the operational rules allow this request?
      -> BUDGET           is an attempt left?  (default: 3, controller-owned)
      -> EXECUTE          the controller calls the executor; the model cannot
      -> VERIFY           the result is typed before anything reads it
      -> RESPOND

The stages are states in an explicit transition table. `Run.advance` is the
only way to change state and it consults that table, so a code path that tried
to reach EXECUTE without passing the gates raises rather than executes.

## Quick start

    uv sync --dev
    uv run pytest -q

The same four gates run in CI (`.github/workflows/local-agent.yml`, scoped to
`local-agent/**`):

    uv lock --check
    uv run pytest -q
    uv run ruff check .
    uv run ruff format --check .
    uv run mypy src tests

## Example

```python
import asyncio, json

from local_agent.contracts import ModelResponse
from local_agent.controller import Controller
from local_agent.model_adapter import ScriptedModelAdapter
from local_agent.policy import RunContext
from local_agent.wiring import build_default_registry

proposal = json.dumps(
    {
        "tool": "file_search",
        "arguments": {"query": "Jeep clutch notes", "root_id": "workspace"},
    }
)

controller = Controller(
    build_default_registry(),
    ScriptedModelAdapter((ModelResponse(structured_output=proposal),)),
)

outcome = asyncio.run(
    controller.run(RunContext(run_id="demo"), [{"role": "user", "content": "find them"}])
)

print(outcome.terminal)  # status='succeeded' attempts=1
print(outcome.result)  # status='success' data=['clutch_replacement.md']
print([s.value for s in outcome.states])
```

Swap the proposal for `"rm -rf /"`, a tool name that does not exist, a call
hidden inside `reasoning=`, or a smuggled `"max_attempts": 999` and the run
ends at a normalized, bounded, audited rejection with the executor untouched.

## The filesystem capability

Three tools. Two are read-only — `workspace.read` and `workspace.list` — and
are what a deployment gets by default. The third, `workspace.write`, is the
first capability in this project that changes anything, and it is described
separately below because acquiring it is a deliberate act: it lives in its own
module, its own registry builder and its own run-context builder, so an
existing read-only deployment cannot gain it by upgrading.

The model sees an abstract namespace of exactly two roots and supplies a
relative path:

```json
{"tool": "workspace.read",
 "arguments": {"root_id": "workspace", "path": "src/app.py"}}
```

`workspace` and `knowledge` are labels. The physical directory each maps to is
chosen by trusted wiring, held in one module, and never appears in a result,
an error message, or an audit event.

```python
from local_agent.wiring import (
    build_filesystem_registry,
    build_filesystem_run_context,
    build_physical_roots,
)

roots = build_physical_roots(
    {"workspace": "/srv/agent/workspace", "knowledge": "/srv/agent/knowledge"}
)
registry = build_filesystem_registry(roots)
context = build_filesystem_run_context("run-1")
```

**Containment.** A path is authorized only when, after full symlink
resolution, it is still inside the resolved root:

    resolved_candidate.is_relative_to(resolved_authorized_root)

That is a component-wise comparison, deliberately not a string prefix test —
`"/srv/workspace_evil/loot".startswith("/srv/workspace")` is `True`, and a test
named for that attack asserts both that the naive check would have been fooled
and that the real one is not.

**Symlinks** are resolved first and the physical target is authorized second: a
link staying inside the root is followed, one landing outside is denied before
any read. Listings never follow a link at all — an entry is labelled `symlink`
without its target being stat'ed, so a link pointing outside discloses nothing.

**Ceilings** are policy authority and no argument schema exposes them: 256 KiB
per file (counted in bytes, not characters), 1,000 directory entries, 1,024
path characters, 512 KiB serialized result. Exceeding one is a rejection, never
a silent truncation.

**Read-only** is structural. There is no write, delete, rename, mkdir, or chmod
tool to route a request to; the executor module calls no mutating method and
opens files only in mode `"rb"`; and both facts are asserted against the
module's own AST.

> The filesystem adapter is read-only and does **not** constitute an OS-level
> sandbox. Path containment protects the capability boundary within the
> configured roots. It does not protect against every operating-system or
> filesystem attack — notably TOCTOU races and hard links, both of which
> presuppose an attacker who can already write inside a root. See
> [`docs/milestone-2-decisions.md`](docs/milestone-2-decisions.md) §12.

## Why the model cannot escalate

| Attack | Why it fails |
|---|---|
| Tool call hidden in reasoning | The parser reads one field; the others are never an input |
| Malformed or multiple JSON calls | One envelope, strictly typed, or `TOOL_CALL_MALFORMED` |
| Shell text (`rm -rf /`) | No shell executor exists to route it to — it is only ever a string |
| Unknown tool name | Resolved against a registry with no mutation API; miss is terminal |
| Arbitrary path as `root_id` | `Literal["workspace","knowledge"]` rejects it at the schema |
| Schema-legal but ungranted root | A separate authorization gate reads grants from frozen config |
| Smuggled `max_attempts` | Boundary models forbid extra fields; the budget lives in `RunContext` |
| Infinite retry loop | Bounded at 3 attempts; identical proposals still consume budget |
| Prompt injection in a tool result | Results are data; nothing re-reads them as instructions |
| Corrupt tool result | Verified against the declared result schema; a bad shape is an error, not a crash |
| `../../etc/passwd` as a path | Refused by the schema before any join or filesystem contact |
| `/etc/passwd`, `C:\x`, `\\server\share`, `~/.ssh` | Same — an absolute path would otherwise *replace* the root when joined |
| Symlink pointing outside the root | Resolved first, then denied; no read occurs |
| Sibling directory `workspace_evil` | Containment is `is_relative_to`, not `startswith` |
| Reaching the other root through a symlink | `root_id` selects the root; the path cannot re-select it |
| A file larger than the ceiling | At most ceiling+1 bytes are ever read; the request is denied, not truncated |
| Instructions inside a file's contents | Returned as data; nothing re-reads a result as control input |
| A tool call written in model prose | Prose arrives on a channel the parser never reads |
| A model service returning 500 MB | At most ceiling+1 bytes are ever read |
| A model service that hangs | Every call has an explicit, configured timeout |
| Malformed or hostile service responses | Schema-validated at the boundary, normalized to existing error codes |
| A model claiming it is authorized | Claims are prose; the gates re-decide every proposal independently |
| A journal edited to grant a different tool | Recovery re-resolves the tool against the live registry and re-derives the execution id |
| A journal edited to widen the retry budget | The budget comes from the live `RunContext`; a disagreeing record is fatal |
| A completion record with no authorization | Rejected as a forged result — the controller never approved that execution |
| A record claiming an unknown type or schema version | Refused before Pydantic sees it; unknown is never "probably fine" |
| A truncated final line after a crash | Never `fsync`-returned, so never durable; dropped, not guessed at |
| Replaying a hostile journal to force a side effect | `replay` takes no executor and cannot reach one |
| A capability declaring itself exempt from authorization | Inadmissible: `destructive` without `requires_authorization` is refused |
| A capability inserted into a live registry | The map is a read-only proxy and the object refuses rebinding |
| A capability schema widened after authorization | The content-addressed digest no longer matches; recovery fails closed |
| A `MUTATING` capability re-run once per retry | Retry consults `re_executable`, not just the error code |
| An executor reading or changing the run's authority | Its whole world is one frozen arguments object |
| A result carrying `authorized`, `max_attempts` or a `policy` object | Fails verification; results are data, never commands |
| An operator approval replayed against a later plan | Recording any decision changes the plan's content-addressed id |
| An operator naming a different tool or arguments | The decision type has no field for either, and forbids extras |
| An operator resuming an ambiguous, non-repeatable execution | Never offered; `available_actions` has no code path for it |
| An operator reviving a terminal run | A terminal plan offers no actions, in every terminal status |
| A `ToolSpec`, policy or grant changed after approval | Re-resolved and re-checked after the decision is durable, before any executor |
| Operator text carrying an instruction to the model | The reason field is a slug charset, and nothing on this path reaches a model |

Each row has a test, and each rejection test also asserts the executor's call
count is zero.

## Talking to a real model

The production adapter speaks LocalAI's OpenAI-compatible
`POST /v1/chat/completions`. It gains no authority: it transports untrusted
output, and every gate above still decides what happens to it.

```python
from local_agent.controller import Controller
from local_agent.model_config import ModelServiceConfig
from local_agent.wiring import build_default_registry, build_model_adapter

config = ModelServiceConfig(base_url="http://127.0.0.1:8080", model="gemma-4-12b")
registry = build_default_registry()
controller = Controller(registry, build_model_adapter(config, registry))
```

**Three channels, one of them eligible.** LocalAI's response message carries
`reasoning`, `content`, and `tool_calls` separately, and they map onto this
project's three channels unchanged. Only `tool_calls` becomes
`structured_output`; prose can never become a proposal, because prose arrives
on a field the parser does not read. If the tool-call channel is missing,
empty, or ambiguous, the adapter fails closed — it never recovers a proposal
from narrative and never infers one from prose.

**Configuration is operator authority.** Base URL, credential, timeout, and
every ceiling live in a frozen, validated `ModelServiceConfig`. The URL is
restricted to `http`/`https`, may not embed credentials, and the API key is
`repr=False` so a stray log line cannot print it. The model supplies none of
these.

**One socket, one module.** `transports/http.py` is the only production module
permitted a network import, granted per module exactly as the filesystem grant
was — the controller, the gates, and even the model adapter itself remain
structurally unable to open a connection.

**Retry stays where it was.** The adapter and transport never retry. Three
controller attempts mean exactly three model calls; a transport retrying inside
a retrying controller would silently make nine.

**Zero new dependencies** — the transport is stdlib `urllib.request` on a
worker thread.

## Running against a real LocalAI

The deterministic suite never needs a model server:

    uv run pytest -q              # no LocalAI, no network, no credentials

The live integration tests are opt-in and marked `live`. They skip when the
gate is absent and **fail loudly** when the gate is present but the service is
missing or misconfigured — an explicitly requested live run must never
degrade into a silent skip.

    export LOCAL_AGENT_LIVE_MODEL=1
    export LOCALAI_MODEL=<a model your instance serves>
    export LOCALAI_BASE_URL=http://127.0.0.1:8080   # or LOCALAI_ADDRESS=:8080
    export LOCALAI_API_KEY=<key>                    # only if your instance needs one
    uv run pytest -m live -q

Variables follow LocalAI's own conventions: `LOCALAI_API_KEY` then `API_KEY`
for the credential, and `LOCALAI_ADDRESS` for the bind address. Because
`LOCALAI_ADDRESS` is a *bind* address (`:8080` means "all interfaces"),
`LOCALAI_BASE_URL` takes precedence and a bare `:8080` is translated to
`http://127.0.0.1:8080`.

Nothing in `src/` reads an environment variable — configuration is
constructed explicitly by trusted wiring, and the live tests do the env
reading themselves.

**Live inference is nondeterministic.** The deterministic replay suite is
entirely scripted and never contacts a model; live output is deliberately kept
out of it. What a live run records is structural only — which channels carried
something, whether the proposal parsed, the normalized error, the controller's
state trace — never model text, a credential, or a filesystem path.

**TLS is never weakened.** There is no custom-CA support, so an instance behind
a self-signed certificate will fail verification; that is a deployment
requirement, not something the tests bypass.

**Normal CI does not require LocalAI**, and PR mergeability does not depend on
live inference.

## Surviving a crash

The controller can be given a journal. It then writes four kinds of record —
run started, execution authorized, execution completed, run terminal — and
each `append` returns only after `os.fsync`, so a record that was returned is
a record that survived.

```python
from local_agent.persistence.journal import RunJournal
from local_agent.persistence.records import new_run_id

run_id = new_run_id()
with RunJournal(f"/var/lib/local-agent/{run_id}.jsonl") as journal:
    controller = Controller(registry, adapter, journal=journal)
    outcome = asyncio.run(controller.run(RunContext(run_id=run_id), messages))
```

**The authorization is written before the executor is called**, not after.
That ordering is the whole design: a crash can then leave an authorization
with no completion, which is a *detectable* ambiguity, whereas writing
afterwards would leave a completed side effect with no record of it at all.

**Recovery re-decides; it does not resume by itself.** `plan_recovery` reads the journal
back and re-validates every record against the *live* registry and run
context — the run id matches, the budget matches, the tool still exists, the
arguments still validate against its current schema, the execution id
re-derives from those arguments, and `side_effect_free` still matches the
`ToolSpec`. Anything that disagrees is a fatal `RecoveryError`, never a
repair. It returns a plan, and acting on that plan is a separate decision:

```python
from local_agent.persistence.journal import read_records
from local_agent.recovery import plan_recovery, replay

records = read_records(path)
plan = plan_recovery(records, registry, RunContext(run_id=run_id))
plan.disposition  # e.g. 'execution_unknown'
plan.may_execute  # only for an authorized, uncompleted, repeatable tool
plan.requires_operator  # True when the system cannot know what happened

replay(records, registry, RunContext(run_id=run_id))  # observe, never execute
```

**Execution identity is content-addressed.** An execution id is
`sha256(run_id, step_id, attempt, tool, canonical arguments)`, truncated to
128 bits. It is derived, never carried from the model or read from the file:
a journal claiming an id that its own contents do not produce is rejected.

**Semantics, stated without hedging.** This system does **not** provide
exactly-once execution in general, and does not use the phrase where it cannot
enforce it. What it provides is:

| Tool | Guarantee | On an ambiguous crash |
|---|---|---|
| `side_effect_free=True` | at-least-once, observationally equivalent to exactly-once *because the tool repeats harmlessly* | recovery may re-execute |
| `side_effect_free=False` (the default) | at-most-once | `execution_unknown`, `requires_operator = True`, stop |

The flag defaults to `False`, so a tool added without thinking about crash
behaviour fails closed. It lives on the frozen `ToolSpec` in trusted wiring;
nothing in a proposal can reach it.

**Replay executes nothing.** `replay` takes no executor and never touches
`ToolSpec.executor` — it reconstructs the observable shape of a run (state
trace, record types, execution ids, terminal status) from the records alone,
so a hostile journal has nothing to trigger. A test asserts this against the
function's own AST as well as behaviourally.

**The journal is a record, not an authority.** Its checksum detects
corruption; it cannot detect tampering, because there is no key to
authenticate with, and the adversarial tests recompute the checksum after
every mutation to make that explicit. What actually defends the system is
re-derivation and re-validation against invariants the file cannot influence.

**What is never written:** credentials, headers, model reasoning or narrative,
raw prompts or responses, tool result payloads, physical filesystem paths, and
exception text. A completion carries a status and a stable reason slug, and
nothing else.

**One writer.** The journal takes an `fcntl.flock` on open; a second live
holder is refused with `JournalLockError`. A lock is chosen over an exclusive
lock file precisely because the kernel releases it when the process dies —
a crashed run is immediately recoverable rather than blocked forever by a
stale lock.

## The capability contract

Every capability is admitted before it exists, and nothing about it can be
changed afterwards by anything the model, an executor or a result can say.

**Admission, not construction.** `ToolSpec` is a frozen dataclass and
dataclasses do not validate, so `ToolRegistry` puts every entry through `admit`
— every time, with no "already checked" marker to forge. It refuses an empty or
path-shaped or uppercase name, a timeout outside `0.001 .. 300`, an
`args_schema` that is not a `BaseModel`, an executor with no `execute`, and two
combinations that are individually well-typed and jointly meaningless:

```python
# refused: `authorize` skips the grant check for a capability that
# does not require authorization, so this one would run ungranted
ToolSpec(name="wipe", destructive=True, requires_authorization=False, ...)

# refused: destroying something while claiming repetition is free
ToolSpec(name="wipe", destructive=True, side_effect=SideEffect.NONE, ...)
```

**Three side-effect values, two derived questions.** A boolean was answering
two different questions at once:

| `side_effect` | `side_effect_free` | `re_executable` | Meaning |
|---|---|---|---|
| `NONE` | True | True | Nothing observable happened. Reading a file. |
| `IDEMPOTENT` | False | True | Something happened; N runs equal one run. |
| `MUTATING` (default) | False | False | The effect compounds. |

Both properties are derived, so they cannot drift, and both refuse assignment.
**Retry is not `side_effect_free`.** The controller's branch is
`error.retryable AND (nothing ran OR re_executable) AND budget remains` — before
this, a failing `MUTATING` capability was re-run once per attempt, producing
three irreversible acts for a budget of three.

**A capability is content-addressed, because immutability cannot reach its
schemas.** `args_schema` and `result_schema` are classes, and Python classes are
mutable — `model_config`, `model_fields` and even the compiled validator can be
replaced. Rather than pretend otherwise, the capability gets a digest over both
JSON schemas plus its declared properties, recorded on `ExecutionAuthorized`:

```python
plan = plan_recovery(journal.records(), registry, run_context)
plan.capability_verified  # False means "no digest recorded", never "assumed fine"
plan.capability_digest  # the definition this execution was authorized under
```

A definition that changed after authorization is then a fatal
`journal_capability_digest_mismatch` — the one case where the arguments still
validate, the execution identity still re-derives, and every other check passes.
Like the journal checksum, it detects drift and not tampering; the executor is
deliberately outside it, so swapping a spy for the production executor keeps the
capability identical.

**The registry is immutable in every direction ordinary code has.** A
`MappingProxyType` map, `__setattr__` and `__delattr__` that refuse, read-only
views, duplicates refused rather than replaced, and no `register`/`replace`/
`remove` to call. The honest limit: `object.__setattr__` defeats this, as it
defeats any in-process guard — which is exactly why the digest exists.

**An executor acts and never decides.** From inside `execute` it can reach no
run context, no grants, no registry, no controller, and cannot mutate its own
arguments; structurally it imports no authority module, constructs no registry
or durable record, and calls no model. `.executor` is reachable from exactly one
production module. It may *deny* via `ToolDenialError` and can never grant.

## The constrained artifact writer

`workspace.write` is the first capability here that does something
irreversible. It exists to test the machinery above against a real effect, not
to become a filesystem API: it replaces the entire content of exactly one
regular file beneath one authorized root, and that is the whole of it.

```python
from local_agent.wiring import (
    build_writable_filesystem_registry,
    build_writable_run_context,
)

registry = build_writable_filesystem_registry(roots)
context = build_writable_run_context("run-1")
```

Separate builders, not a `writable=True` flag. A flag is one edit away from
being passed by a caller who did not think about it; a differently-named
function has to be typed on purpose.

**Containment is reused, and the reuse has a twist.** There is one containment
implementation in this package, so a traversal bug would have one place to
live. But `_resolve_within_root` resolves with `strict=True` and cannot resolve
a file that does not exist yet, so the writer resolves the destination's
*parent* through it and handles the one remaining component itself. That falls
out well: a missing parent is a refusal, which is how "never creates
directories" is enforced — there is no `mkdir` here to forget to guard.

**The leaf is opened with `O_NOFOLLOW`, and that is the security property.** A
pre-flight "is it a symlink?" test is racy by construction; the flag moves the
check into the same syscall as the open, so the kernel refuses instead of this
code hoping. A test patches `is_symlink` to lie exactly once — precisely what
winning that race achieves — and the bytes still do not land outside the root.

Note what the flag does *not* cover. It guards the final component only, so a
symlinked parent directory is followed happily; that is measured, and it is
what makes the strict parent resolution load-bearing rather than tidy.

**Classified `IDEMPOTENT`, under a bound that is stated rather than implied.**
Running the identical request N times leaves the same file with the same bytes
as running it once. Filesystem *metadata* is outside that bound — `mtime`
advances every time and a test asserts that it does, so the limitation stays
visible. The classification is what lets the controller retry a failed write:
`re_executable` is True while `side_effect_free` is False, which is exactly the
distinction Milestone 7 refused to collapse into a boolean.

**What it does not claim.** Not atomic — `O_TRUNC` empties the file at open, so
a crash mid-write leaves a file shorter than either version. Not transactional,
not exactly-once. What it does claim is bounded and tested: the bytes are
`fsync`ed before the call returns, and nothing is ever written outside the
authorized root.

## Operator-controlled recovery

Milestone 5 stopped at a plan. This layer lets a human act on one without
becoming a general execution mechanism. The whole design is one sentence:

> The operator may say **"I approve this exact controller-generated plan."**
> The operator may not say **"execute this."**

**The plan is controller-generated and content-addressed.** Its id is a hash
over everything that decides what is being approved — disposition, tool,
canonical arguments, execution identity, budget, available actions, and the
number of decisions already recorded. An operator cannot construct a plan and
have it believed, because the controller re-derives the id from the journal
every time and compares.

**Only valid actions are offered.** `available_actions` is derived from the
run's state, so an action absent from it has no code path, not merely no
permission:

| Disposition | Offered |
|---|---|
| `terminal` | *nothing* |
| `execution_pending_repeatable` (gates still pass) | resume, abort, terminalize, acknowledge, reject_recovery |
| `execution_unknown` | abort, terminalize, acknowledge, reject_recovery |
| `execution_completed` | abort, terminalize, acknowledge, reject_recovery |
| `no_execution_authorized` | abort, terminalize, acknowledge, reject_recovery |

**`execution_unknown` is never offered a resume**, and that restriction is
deliberate. The tool is not side-effect free and the journal cannot say whether
the effect happened, so letting the operator overrule it would be a human
asserting a fact the controller cannot verify. The cost is real: an operator who
*knows* the effect did not happen must still start a new run.

```python
from local_agent.operator import OperatorDecision, inspect_run, render_inspection

with RunJournal(path) as journal:
    print(render_inspection(inspect_run(journal.records(), registry, run_context)))

    plan = plan_recovery(journal.records(), registry, run_context)
    decision = OperatorDecision(
        run_id=plan.run_id,
        plan_id=plan.plan_id,  # bound to this exact plan
        action="resume",  # chosen from available_actions
        decision_sequence=plan.next_decision_sequence,
        reason_code="verified_no_duplicate_effect",  # a slug, never prose
        expected_execution_id=plan.execution_id,
    )
    outcome = asyncio.run(controller.recover(run_context, decision, messages))
```

**The decision has no vocabulary for execution.** No `tool`, no `arguments`, no
`max_attempts`, no `root_id`, no `side_effect_free`, no executor selector — and
`extra="forbid"`, so adding one in transit is a schema violation. The threat
model's prohibitions are not rules the code checks; they are sentences the type
cannot express. `reason_code` is constrained to `^[a-z][a-z0-9_]{0,63}$`, a
charset that cannot spell an instruction or a JSON payload.

**An approval cannot be replayed.** The plan id covers the decision count, so
*recording* a decision changes the plan's identity. The approval that produced
plan A does not name any plan that exists afterwards — staleness is structural
rather than a rule someone has to apply.

**Everything is re-established before the executor runs.** After the decision is
durable, the controller re-reads the journal, re-derives the plan, re-resolves
the `ToolSpec`, re-validates the arguments against its *current* schema, re-runs
both gates, and re-derives the execution identity. An approval is a statement
about a moment, and the moment ends when the decision is recorded.

**Resume re-enters the ordinary path.** There is no recovery executor. `run()`
and `recover()` share one loop; a resume differs only by taking its operation
from the journal instead of the model, then walking the same gates in the same
order to the same states. It reuses the original authorization rather than
writing a second one, so a recovered run ends with exactly one authorization,
one execution identity, and one completion.

**Recovery never calls the model** — not to plan, not to validate, not to decide
whether resuming is safe — and a successful recovery tells the model nothing
about itself. Path A (an ordinary run) and Path B (crash → approve → resume)
produce the same verified result, the same terminal, and the same state trace;
the journals differ by exactly one audit record.

**Abort is not a tool failure.** No synthesised exception, no completion record,
no fabricated result, no further generation:

```
RECOVERY_REQUIRED → operator abort → persist decision → ABORTED → terminal
```

And it never rewrites ambiguity into failure. After aborting an
`execution_unknown` run the journal still holds an authorization with **no**
completion, beside the operator decision and an `aborted` terminal — so nobody
reading it later can mistake an unknown outcome for a non-execution.

**No admin mode exists.** There is no `--force`, `--unsafe`, `--ignore-policy`,
`--bypass`, `--superuser` or `--emergency`, in any form. If recovery is blocked,
the answer is a new run.

**No operator identity is claimed.** The project has no authentication model, so
no `operator` field is persisted — an unauthenticated name would record a claim
while implying a verified fact. The interface is a trusted local control surface,
and saying so is more honest than a field that looks like attribution.

## Layout

    src/local_agent/
      contracts.py      typed boundary models (frozen, extra="forbid")
      state_machine.py  State enum + explicit transition table
      registry.py       ToolSpec, ToolRegistry, ToolExecutor protocol
      policy.py         RunContext (frozen authority) + the two gates
      controller.py     the orchestrator — the only component with authority
      model_adapter.py  ModelAdapter protocol + deterministic fake
      events.py         structured audit records (no secrets, no wall clock)
      wiring.py         trusted startup assembly
      model_config.py   frozen, validated model-service configuration
      model_transport.py the transport seam + deterministic scripted transport
      model_service.py  the production LocalAI adapter
      recovery.py       crash-recovery planning + observational replay (pure)
      operator.py       operator control plane — decisions, binding, inspection
      registry.py       the capability contract — admission, identity, immutability
      executors/
        file_search.py  the Milestone 1 deterministic fake
        workspace_fs.py the only module permitted to *read* a workspace
        workspace_write.py the only module permitted to *write* one
      persistence/
        records.py      versioned durable record contracts (pure, no I/O)
        journal.py      the only module permitted to write durable state
      transports/
        http.py         the only module permitted to touch the network

## Scope

**Implemented:** deterministic controller, state machine, model adapter
interface, tool specification, `ControllerError`, `ToolFeedback`, typed result
boundary, authorization, policy, retry budget, parser boundary, audit events, a
read-only filesystem capability, a production model adapter over LocalAI's
OpenAI-compatible endpoint, a durable run journal with crash recovery and
observational replay, an operator control plane with bound approvals and
auditable resume, one constrained artifact writer, and the test suite.

**Deliberately absent:** every filesystem mutation other than replacing one
regular file — no delete, rename, mkdir, chmod, copy or append — shell or
subprocess execution,
Playwright or any browser, network access outside the model transport, MCP,
Docker code execution, Qdrant, SQLite, Gemma, llama.cpp, OS-level sandboxing,
distributed coordination, a CLI binary, authenticated operator identity, and
automatic *unattended* resumption — recovery produces a plan, and acting on it
always requires an explicit, bound operator decision.
`tests/test_architecture.py` enforces this against the package's own AST, with
each filesystem grant scoped to one named module — the absence is checked, not
merely stated. Reading and writing are separate grants held by separate
modules, so the reader cannot mutate and the writer cannot browse.

## Further reading

- [`docs/milestone-1-decisions.md`](docs/milestone-1-decisions.md) — controller conflicts, resolutions, deviations
- [`docs/milestone-2-decisions.md`](docs/milestone-2-decisions.md) — filesystem path model, symlink policy, ceilings, and known limitations
- [`docs/milestone-3-decisions.md`](docs/milestone-3-decisions.md) — model API selection, channel mapping, transport boundary, and what determinism does and does not mean here
- [`docs/milestone-4-decisions.md`](docs/milestone-4-decisions.md) — live-integration gate semantics, credential handling, and what remains unobserved
- [`docs/milestone-5-decisions.md`](docs/milestone-5-decisions.md) — durable state architecture, crash windows, execution semantics, and the proven/assumed/not-guaranteed split
- [`docs/milestone-6-decisions.md`](docs/milestone-6-decisions.md) — operator authority, approval binding, revalidation, abort semantics, and why there is no operator identity
- [`docs/milestone-7-decisions.md`](docs/milestone-7-decisions.md) — the capability contract, the authority matrix, admission, side-effect and retry semantics, and the requirements a future side-effecting capability must satisfy
- [`docs/milestone-8-decisions.md`](docs/milestone-8-decisions.md) — the constrained artifact writer: path containment under a write, the file-type policy and the liveness finding behind it, size-limit ownership, the bounded idempotency claim, and what is deliberately not guaranteed
- [`CLAUDE.md`](CLAUDE.md) and [`.claude/rules/`](.claude/rules/) — working rules for this subproject
