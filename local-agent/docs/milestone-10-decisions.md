# Milestone 10 — State Machine Coherence Under Composition

**Status: STOPPED before production code.** Phase 1 inspection found that the
existing model/proposal contract has no representation for *"another execution
is requested"* or *"no further execution is required"*. Under the Phase 1
instruction — *"A missing contract is a finding, not an invitation to invent
architecture"* — this document records the finding, the design that is ready to
proceed once the contract question is settled, and the alternatives that were
rejected and why.

No production file was modified. The repository remains at the M9 baseline.

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

## 4. Composition mechanism — the blocking finding

The intended shape was: a successful execution may proceed to another
execution **when the existing contract explicitly requests one**. Phase 1's
first task was to determine how that request is represented. It is not.

### What the contract can express

Measured, not inferred:

| Type | Fields | Extra fields |
|---|---|---|
| `ModelResponse` | `reasoning`, `narrative`, `structured_output` | forbidden |
| `RawToolCall` | `tool`, `arguments` | forbidden |
| `ModelRequest` | `run_id`, `step_id`, `attempt`, `messages`, `feedback` | forbidden |

`ModelResponse(structured_output=None, done=True)` raises `ValidationError`.
`RawToolCall(tool="x", arguments={}, final=True)` raises `ValidationError`.
Neither type has vocabulary for completion or continuation, and `extra="forbid"`
means that is enforced rather than conventional.

### Why the absence of a proposal cannot be reused as "done"

The only signal available is presence or absence of a tool call on the
structured channel — and that is **already bound, by design and by a named
test, to a different meaning**.

`model_service.py` states it three times in its own docstrings:

> *"Fail closed, never fall back. If `tool_calls` is absent, empty, or
> ambiguous, `structured_output` is `None` and the controller's existing parser
> returns `TOOL_CALL_MALFORMED`."*

> *"Zero calls: the model answered in prose, which is not a proposal."*

> *"Returning `None` is the fail-closed path: the controller's parser then
> reports `TOOL_CALL_MALFORMED`, the model is asked to try again, and the
> attempt is charged to the existing budget."*

`tests/test_model_adapter.py::test_a_response_with_no_tool_call_fails_closed`
pins it: *"Prose is not a proposal. There is no fallback to narrative."*

Measured end to end: a run whose model answers only in prose makes 3 model
calls, walks `GENERATE → PARSE → FEEDBACK → RETRY` three times, and terminates
`failed` with `RETRY_EXHAUSTED`. `TOOL_CALL_MALFORMED` is in `RETRYABLE_CODES`.

**So adding `RESPOND → GENERATE` alone does not produce composition — it
produces a broken run.** E1 would succeed, the controller would ask again, a
model with nothing further to do would answer in prose, and the run that did
exactly what was asked would be reported as `RETRY_EXHAUSTED / failed`. This is
the concrete reason the Phase 1 instruction warned against assuming that edge
was sufficient.

Reinterpreting absence as completion would require:

* inverting a test whose name ends in `_fails_closed`, which Step 2 forbids;
* making the same wire value mean "error, retry" at execution 1 and "success,
  stop" at execution 2 — position-dependent semantics on a security boundary;
* and, most seriously, making **model silence mean task success**. A truncated
  response, a transport hiccup yielding empty content, or a prompt injection
  that suppresses the tool-call channel would all terminate a run as
  *succeeded* — including a run whose last act was a `MUTATING` execution. That
  is the exact inverse of the fail-closed-on-ambiguity discipline that
  Milestone 5's `execution_unknown` and Milestone 9's `unknown ≠ failed`
  established.

The architecture needs to distinguish *"I have completed the task"* — an
affirmative statement — from *"I produced nothing"* — an absence. Today it has
only the second, and it already means something else.

### The smallest missing contract

Two things are missing. Both are small; neither may be invented unilaterally.

**(A) An affirmative completion signal.** The model must be able to say, on a
channel the controller already trusts, that no further execution is required.
Two candidate shapes, with the trade-off stated honestly:

*A1 — a second envelope on the existing structured channel.* The model emits a
distinct JSON shape (e.g. `{"done": true}`); `parse_candidate` gains one branch
returning a completion sentinel instead of a `RawToolCall`. No new
`ModelResponse` field; absence still means malformed, so the fail-closed test
stands unchanged. Smallest new surface. Depends on model compliance: a model
that never emits it composes until the §4(B) ceiling stops the run, which is
safe but is a real limitation.

*A2 — map the wire protocol's own `finish_reason`.* The OpenAI-compatible
schema carries `choices[].finish_reason` (`"tool_calls"` versus `"stop"`).
`_ExternalChoice` currently declares only `message`; the adapter never reads
it. This is the most faithful "the contract already carries this, we simply
decline to look" option, and the signal is produced by the runtime rather than
by prompt compliance. **But** Milestone 4's live path remains unobserved — no
LocalAI instance has ever been reached — so whether the deployed service
populates `finish_reason` is an assumption, not a measurement. Building the
composition contract on an unverified wire field would put a load-bearing
semantic on something no test has seen.

Recommendation: **A1**, on the grounds that it depends only on machinery the
deterministic suite already proves end to end, and that A2 can be added later
as a corroborating signal without changing the controller. This is a
contract decision and belongs to the project owner, not to this document.

**(B) A run-level bound on the number of executions.** With a per-execution
retry budget and a model-driven continuation signal, nothing bounds how many
executions a run may compose — a model that proposes forever would compose
forever. `RunContext` is already the owner of every operational ceiling
(`max_attempts`, `max_results_ceiling`, `FilesystemLimits`), and
`records.MAX_OPERATOR_DECISIONS_PER_RUN` is the existing precedent for bounding
a per-run count that the durable store must also respect. A `max_executions`
ceiling there is consistent with existing structure rather than a new
subsystem — but it is still a new authority field, and it is recorded here as
required rather than added.

Note that (B) is required *whichever* form (A) takes, and that it is what
answers §6 of the Phase 1 question list ("how does it prevent accidental
infinite generation") without a `while True`.

## 5. Step identity — designed, not implemented

`step_id` is currently `f"{run_context.run_id}-s1"`, a literal. The design is a
monotonic counter incremented once per *authorized execution*, giving
`{run_id}-s1`, `-s2`, `-s3`. Deterministic because it derives from a count the
controller owns, not from a timestamp, a UUID, or model output; and it feeds
`derive_execution_id`, so two executions of the same capability with identical
arguments in the same run are already distinct executions by identity.

Resume must continue to take its `step_id` from `_ResumeSeed` rather than
recomputing it, exactly as it does today, or a resumed execution would acquire
a new identity and recovery would reject its own journal.

## 6. Termination condition — blocked on §4

A run ends when the model affirmatively signals completion (§4A), when the
execution ceiling is reached (§4B), when an execution fails non-retryably or
exhausts its per-execution budget, or when an operator terminates it. The first
two do not exist yet, which is why this milestone stops here.

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
