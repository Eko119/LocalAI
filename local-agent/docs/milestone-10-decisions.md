# Milestone 10 — State Machine Coherence Under Composition

Phase 1 stopped: the model-facing contract had no affirmative representation for
*"no further execution is requested"*, and the only available signal — absence
of a tool proposal — was already committed, by design and by a named test, to
meaning *malformed, retry*. That finding was accepted and the contract question
resolved by decision rather than by reinterpretation.

**Phase 2 implements the resolution.** The M9 invariant stands untouched:
absence of a structured tool proposal is still failure, never completion.

## 1. Baseline

HEAD `22c4d7fff43836294eed9ebd08160a09d2ba65e0`, working tree clean.
`uv lock --check` current; `ruff check` clean; `ruff format --check` 60 files;
`mypy src tests` clean over 45 source files; **1388 passed, 6 skipped**.
Named suites: architecture 234, M8 157, M9 115, determinism 52,
recovery + operator 134.

## 2. Execution and run boundaries

Established by Phase 0 inspection and unchanged here.

**Run-global:** `run_id`, `max_attempts`, `authorized_tools`,
`authorized_roots`, `allow_destructive`, `max_results_ceiling`,
`FilesystemLimits`, and the `RunStarted` / `RunTerminal` records.
`RunTerminal` carries no execution id, which is correct — terminating ends the
run, not an execution.

**Execution-local:** `step_id`, `tool`, `arguments`, `execution_id`,
`side_effect_free`, `capability_digest` (all on `ExecutionAuthorized`), plus
`status` and `reason` on `ExecutionCompleted`.

**Attempt-local:** `attempt`, and the derived `tool_call_id`
(`{step_id}-a{attempt}`). `attempt` participates in `derive_execution_id`, so
two attempts at the same logical operation are already distinct executions by
identity.

**Capability-local:** the immutable `ToolSpec` and its digest.

The semantic axes are already execution-local at every point they are read.
Every production read of `side_effect_free` and `re_executable` is scoped to a
single `spec` or a single record; there is no run-level aggregate anywhere.

## 3. Retry budget — decided: per execution

**`max_attempts` is per execution.** Authorized in Phase 1 and recorded here.
There is no run-wide retry pool.

Phase 0 measured that the three candidate scopes are currently
*indistinguishable*: `attempt` is initialised once per `_loop` call, and one
`_loop` call is one run is one execution. Composition forces the choice, and
per-execution is the right one because the budget's purpose is to bound the
*repair loop for one proposal*. A model that needs two attempts to get E1's
arguments right has not spent anything that should be denied to E3.

The consequence must be stated plainly rather than discovered later: a run
composing N executions can make up to N × `max_attempts` model calls and up to
N × `max_attempts` executor invocations in the worst case. That is the accepted
cost of a per-execution budget, and it is why §4 below requires a *separate*
run-level bound on the number of executions. The budget bounds repair; it does
not bound composition, and conflating the two would be the same category error
Milestone 8 recorded when it asked a containment mechanism to cover an
availability failure.

## 4. Composition mechanism and the completion contract

### The Phase 1 finding, preserved

`ModelResponse` carries exactly `reasoning`, `narrative`, `structured_output`;
`RawToolCall` exactly `tool` and `arguments`; both forbid extra fields, so
neither could express completion — verified by construction. The one available
signal, presence or absence of a tool call, is bound by
`test_a_response_with_no_tool_call_fails_closed` and by three docstrings in
`model_service.py` to the fail-closed malformed path. Measured: a prose-only
response makes 3 model calls and terminates `failed / RETRY_EXHAUSTED`.

That is why `RESPOND → GENERATE` alone would have produced a broken run rather
than composition, and why reinterpreting absence as completion was rejected:
it would have made model silence mean task success, inverting the fail-closed
discipline M5 and M9 established.

### The chosen shape: `ExecutionComplete`

```python
class ExecutionComplete(_Strict):
    type: Literal["execution_complete"]
```

One field, no default, on the structured channel the controller already trusts.
The reasoning behind each property:

**Why a `type` tag rather than a boolean.** `type: Literal[...]` is the
project's existing discriminator convention — every durable record in
`records.py` carries one. A boolean like `{"complete": true}` would raise the
question of what `{"complete": false}` means, and a field whose false value is
meaningless is a field that will eventually be misread.

**Why the tag is required rather than defaulted.** The records use
`type: Literal["run_started"] = "run_started"` because they are constructed in
Python. This one arrives from the wire, so a default would make the empty
object `{}` validate as completion — reintroducing exactly the
absence-means-completion hazard Phase 1 rejected. The tag is required, so
completion must be stated.

**Why `RawToolCall` is left alone.** The brief requires both semantics to be
explicit but permits the wire representations to differ. A proposal is already
explicit by carrying `tool` and `arguments`. Adding a symmetric tag to
`RawToolCall` would change every existing proposal payload for no semantic
gain. `RawToolCall` is unmodified.

**Why confusion is structurally impossible.** Both types set
`extra="forbid"`. A payload carrying both a tag and tool fields validates as
neither: `{"type": "execution_complete", "tool": "x"}` is rejected by
`ExecutionComplete` for the extra field, and
`{"tool": "x", "arguments": {}, "type": "execution_complete"}` is rejected by
`RawToolCall` for the same reason. Ambiguity is refused by the schemas, not by
a precedence rule someone could later reorder.

**One parser, not two.** `parse_candidate` returns
`RawToolCall | ExecutionComplete`, dispatching on the presence of the `type`
key. Architecture rule 10 forbids a second parser beside it, so completion is
recognised inside the existing boundary rather than in a sibling function. A
payload carrying `type` with any other value is rejected outright rather than
falling through to the proposal branch — fail-closed on an unrecognised tag.

**Absence is unchanged.** `structured_output` that is `None`, empty, or
unparseable still yields `TOOL_CALL_MALFORMED`. The M9 invariant is untouched
and its test is unmodified.

## 5. Execution ceiling — `max_executions`

**`max_executions` is a run-level composition ceiling, constitutionally
distinct from `max_attempts`.** They answer different questions and neither is
derived from, decremented by, or substituted for the other:

| | question | scope | default |
|---|---|---|---|
| `max_attempts` | how many attempts may *this execution* receive? | execution | 3 |
| `max_executions` | how many independent executions may *this run* contain? | run | 1 |

For `max_executions = N` and `max_attempts = M` the worst case is N × M
attempts, with each axis retaining independent meaning.

**Why the default is 1.** It reproduces the pre-M10 contract exactly: a run
composes one execution unless a deployment asks for more. Composition is
opt-in, in the same spirit as the three separate registry builders M8 and M9
established — a stronger capability has to be requested by name.

**Ownership.** `RunContext`, alongside `max_attempts`, `max_results_ceiling`
and the filesystem limits. It is a run-level operational ceiling and that is
already the structure that owns those; no new subsystem, no manager, no
scheduler.

**The ceiling is checked after parsing and before authorization.** A proposal
arriving when the ceiling is already consumed is refused at the authority
boundary, so it never reaches VALIDATE, AUTHORIZE, POLICY_CHECK or the
executor. The refusal is `POLICY_DENIED`, which is already non-retryable, so
it consumes no retry budget and does not increment any attempt counter. The run
terminates failed with an auditable `execution_ceiling_exhausted` event.

**Why the controller asks even when the ceiling is full.** The alternative —
stop asking once capacity is gone and terminate successfully — was rejected. It
would report a run as *complete* when the model may have had further work,
which conflates "the ceiling was reached" with "the task is finished". Those
are exactly the kind of two facts this milestone exists to keep apart, and
reporting truncation as success is the silent-truncation failure the brief
forbids. So the model is always asked, and a proposal it makes beyond the
ceiling is refused loudly.

## 6. Composition and termination

A run ends in exactly one of these ways, each deterministic:

* **explicit completion** — the model returns `ExecutionComplete`; the run
  terminates `succeeded`;
* **ceiling exhausted** — the model proposes when `execution_count >=
  max_executions`; the run terminates `failed` with `POLICY_DENIED`;
* **execution failure** — an execution fails non-retryably or exhausts its own
  `max_attempts`, exactly as before;
* **operator termination** — `abort` or `terminalize`, unchanged.

Absence of a proposal remains `TOOL_CALL_MALFORMED`, retried within the current
execution's budget, terminating `RETRY_EXHAUSTED`. Unchanged from M9.

## 5b. Step identity

`step_id` becomes `f"{run_id}-s{execution_index}"` where `execution_index` is a
controller-owned counter incremented once per *authorized execution* — not per
attempt. A retry of E2 stays within E2's attempt sequence and keeps `-s2`; it
never becomes E3. The counter derives from nothing external: no wall clock, no
UUID, no randomness, no model output.

Resume continues to take its `step_id` from `_ResumeSeed`. A resumed execution
is not a new execution, and assigning it a fresh step id would change its
execution identity and make recovery reject its own journal.

## 7. Replay coherence

Phase 0 found (G2) that `replay` reconstructs state sequences the live machine
forbids: given a three-execution journal it produced `VERIFY → PARSE` twice,
both absent from `TRANSITIONS`. `replay` appends states to a list without
consulting the authoritative transition relation.

This is observational rather than a security hole — replay takes no executor
and never feeds the controller — but "state machine coherence under
composition" is precisely this milestone's subject, and here the reconstruction
and the authority table disagree. The correction is to validate each
reconstructed transition against `TRANSITIONS`, which also makes replay a
second, independent check that the journal describes a run the controller could
actually have produced.

**This correction is independent of §4 and could land on its own.** It is
recorded here rather than applied because Phase 1's Step 3 sequences it after
the composition mechanism, and applying half a milestone's production changes
while its central contract is unresolved would leave the tree in a state
neither M9 nor M10.

## 8. Recovery semantics

No change required, and this is the strongest evidence that composition is not
architecturally forbidden. Measured in Phase 0 against synthetic
three-execution journals:

* E1 complete, E2 complete, E3 pending → disposition `execution_unknown`, tool
  `workspace.append`, `step_id` `-s3`, `side_effect_free` False,
  `re_executable` False, actions `abort / terminalize / acknowledge /
  reject_recovery`, **no resume**. The run is not converted wholesale to
  unknown; the uncertainty is localised to E3.
* Two simultaneously pending executions → `RecoveryError(
  "journal_multiple_pending_executions")`. Fail-closed and correct.
* All complete → the plan describes `list(authorizations)[-1]`, the highest
  sequence. Earlier executions are read and validated but not surfaced in the
  plan (Phase 0 gap G4) — defensible for a resume decision, incomplete as a
  description of the run.

## 9. M6 compatibility

M10 is an intentional extension of the M6 single-execution contract, and M6
remains historically accepted. Precisely:

* M6 established how a **successful execution terminates** for the
  single-execution controller that then existed. That contract was correct for
  the architecture it described.
* M10 extends the controller to permit **subsequent executions** after a
  successful one. It changes composition, not the meaning of a successful
  execution.
* The execution-local authority semantics established by M6, M7, M8 and M9 —
  admission, capability identity, the digest, the three-valued side-effect
  classification, both derived properties, the retry gate, the recovery
  dispositions, and the operator's execution-bound terminal decisions — remain
  intact and unmodified.
* M6's §22.8 documented deviation rested on the observation that a successful
  single-tool run terminates through `RESPOND → TERMINAL`. M10 adds an
  alternative outgoing edge; it does not remove that one. A run that composes
  one execution still terminates exactly as M6 described.

M6 history is not rewritten.

## 10. Determinism

Nothing in the design introduces wall-clock time, randomness, iteration-order
dependence or ambient state. Step ids come from a controller-owned counter;
execution ids are content hashes; journal ordering comes from the recorded
sequence, with duplicates and gaps refused. Phase 0 confirmed no dependency on
set iteration, filesystem enumeration or timestamps anywhere in the ordering
path.

## 11. Rejected alternatives

**Treating "no tool call proposed" as run completion.** Rejected for the three
reasons in §4: it inverts a named fail-closed test, it makes one wire value
mean two different things depending on position, and it makes model silence
indistinguishable from task success. This is the alternative that would have
let Phase 1 proceed today, and rejecting it is the substance of this document.

**A `has_more` / `continue_execution` boolean on `ModelResponse`.** This is on
the Phase 1 prohibition list, and rightly: it is a control field on an
untrusted channel. Note that A1 in §4 is *not* this — a completion envelope on
the structured channel is a proposal-shaped statement the parser validates,
not a boolean the controller obeys.

**A caller-supplied plan or step list.** That is a workflow, and it would move
the decision of *which capabilities run* from the model's proposals to a
static structure. Explicitly out of scope.

**A scheduler, execution queue, orchestrator or DAG.** Not needed and not
built. Phase 0 confirmed no such abstraction exists in `src/` — the only
matches for those terms are a docstring calling the authority pipeline a
"pipeline" and three disclaimers saying *not transactional* and *not
rollback-safe*. Composition needs the existing loop to be allowed to go round
again, not a manager for a list of operations.

**`while True` with an implicit termination heuristic.** Prohibited, and in any
case it is the same thing as the first rejected alternative wearing different
clothes.

## 12. Findings

**PROVEN** (Phase 0 and Phase 1 measurement, unchanged baseline):

* The live controller performs exactly one execution per run. Two valid
  proposals produce one execution, one model call, and one payload on disk.
* `TRANSITIONS[RESPOND] = {TERMINAL}` and `TRANSITIONS[TERMINAL] = {}`; a
  second execution after a successful first is unreachable, not merely
  un-implemented.
* The journal, `plan_recovery` and `replay` already accept and reason over
  multi-execution histories; mixed semantics are localised correctly.
* Two simultaneously pending executions fail closed.
* Three distinct capability digests, three distinct execution identities, and
  per-record `side_effect_free` — no run-level aggregate exists.
* `ModelResponse` and `RawToolCall` cannot express completion or continuation;
  both refuse extra fields.
* A prose-only response terminates a run `failed / RETRY_EXHAUSTED` after 3
  model calls, so `RESPOND → GENERATE` alone would break composition rather
  than enable it.
* `replay` reconstructs `VERIFY → PARSE`, a transition absent from the
  authoritative table.

**ASSUMED:** everything M5–M9 assumed (`fsync` durability, append ordering,
advisory `flock`, POSIX semantics, `O_NOFOLLOW` and `O_APPEND` honoured,
trustworthy configured roots, no in-process circumvention of the registry).

**UNPROVEN:** that any deployed LocalAI instance populates
`choices[].finish_reason` — M4's live path has never been observed, which is
the specific reason option A2 in §4 is not recommended over A1. Also unproven:
that a model will comply with an affirmative completion signal, which is why
§4(B)'s ceiling is required rather than optional.

**DEFERRED:** the composition implementation itself, pending the §4 contract
decision. The `replay` transition-coherence correction (§7), which is
independent and could land separately. Phase 0 gap G4 (recovery plans describe
only the latest execution when none is pending). Enforced execution deadlines
— M8's `timeout_seconds` debt, carried forward unchanged and still not
silently made to look enforced.
