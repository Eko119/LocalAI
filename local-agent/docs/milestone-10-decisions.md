# Milestone 10 — The Composition and Recovery Contract

**This document is authoritative.** Where the implementation and this document
disagree, the implementation is wrong. It supersedes the Phase 0/1/2 working
notes that previously occupied this file, including the `{"type":
"execution_complete"}` envelope shape that was designed, found unreachable
through the production adapter, and replaced (§3.7 records why).

Its subject is one question: *can this controller compose several executions
inside one run while each execution keeps its own independent semantic
classification, authorization, identity, journal evidence, retry behaviour,
recovery disposition and terminal-state semantics?* It is not a workflow
engine, a DAG, a scheduler or a transaction manager, and nothing below
introduces one.

---

## 1. The central distinction

Everything in this contract descends from one sentence:

> **A fresh run may compose. A recovered run may only restore.**

A fresh run, having verified an execution, asks the model whether more work is
wanted. That question is an *orchestration decision*, and it belongs to the
run's forward progress.

A recovered run makes no such decision. Recovery restores and completes the
execution that was already authorized at the interruption boundary, and then
stops.

The danger this guards against is subtler than a wrong answer. If recovery were
allowed to continue past the restored execution, its semantic role would change
silently — from *restoration* into *run extension*. The model that produced the
original proposal never saw the interruption, never saw the operator's
decision, and holds none of the orchestration context that a post-recovery
"what next?" turn would pretend it holds. Manufacturing that turn would invent
a decision point that did not exist when the run was interrupted, and would
attribute it to a model that was never asked. A run that crashed after
execution 2 and was resumed would then quietly become a run that chose to
perform execution 3 — a choice nobody made.

So the boundary is not a testing convenience. It is a statement about what
recovery *is*.

---

## 2. Vocabulary

These four words are used precisely throughout, and conflating any two of them
is the failure mode this milestone exists to prevent.

A **run** is one invocation of the controller against one `RunContext`. It owns
`run_id`, the grants, `max_attempts`, `max_executions`, and exactly one
`RunStarted` and at most one `RunTerminal` record.

An **execution** is one authorized capability invocation that the controller
verified. It owns `step_id`, `execution_id`, a tool, a canonical argument set,
a `capability_digest`, and a side-effect classification. Executions within a
run are independent: nothing about execution 2 is derived from execution 1, and
no run-level aggregate of their semantic properties exists anywhere.

An **attempt** is one try at an execution. It owns `attempt`, the derived
`tool_call_id` (`{step_id}-a{attempt}`), and — because `attempt` participates
in `derive_execution_id` — its own execution identity. Two attempts at "the
same" logical operation are already distinct by identity, which is deliberate:
the journal must be able to say which physical call happened.

An **execution slot** is one unit of the run's `max_executions` capacity.
Slots are consumed by *authorizing new executions*, never by attempts and never
by restoring an execution that already holds one.

---

## 3. Fresh-run composition

### 3.1 What creates an execution boundary

An execution boundary is created by exactly one thing: the controller entering
`RESPOND` after `VERIFY` accepted a result. At that instant, and only there:

1. `executions_completed` increments;
2. `execution_finished` is recorded, carrying the step id and the new count;
3. `execution_index` increments — a *new slot is opened*, not consumed;
4. `step_id` is recomputed as `f"{run_id}-s{execution_index}"`;
5. `attempt` resets to 1;
6. `feedback` is cleared to `None`;
7. the machine advances `RESPOND → GENERATE`.

Nothing else creates a boundary. A retry does not; a rejection does not; a
failed execution does not; an operator decision does not.

Note the ordering in step 3: the counter is incremented *after* one execution
verifies, so `execution_index` names the slot the controller is about to offer,
and the ceiling test (§5) asks whether that slot exists. This is why the test
reads `execution_index > max_executions` rather than `>=`.

### 3.2 When an execution receives its identity

At the write-ahead boundary — after `POLICY_CHECK` passed and before the
executor is invoked:

```python
execution_id = derive_execution_id(run_id, step_id, attempt, tool, canonical_args)
```

Identity is therefore content-addressed over four controller-owned facts
(`run_id`, `step_id`, `attempt`, the *resolved* tool name) and one
model-influenced fact (the arguments) — and the arguments reach the hash only
after schema validation, authorization and policy have all accepted them. The
model can change *which* execution it is proposing; it cannot choose an
identity, cannot reuse one, and cannot make two different operations share one.

The identity is durable before any physical effect is possible. That ordering
is what makes a crash detectable rather than silent: an `ExecutionAuthorized`
with no matching `ExecutionCompleted` is precisely the ambiguous window.

### 3.3 Attempt lifecycle

`attempt` begins at 1 for every execution. It increments only on the retry edge
(`FEEDBACK → RETRY → GENERATE`), and only when all three of the following hold:
the error is in `RETRYABLE_CODES`, the invoked capability is `re_executable`
(or no capability was reached), and `attempt < max_attempts`. It resets to 1
only at a composition boundary (§3.1).

`attempt` is bounded by `max_attempts`, which is **per execution**. There is no
run-wide retry pool. A model that needed two attempts to get execution 1's
arguments right has spent nothing that execution 3 is owed.

The stated consequence, so it is never discovered later: a run composing N
executions may make up to N × `max_attempts` model calls and up to
N × `max_attempts` executor invocations. That is the accepted cost of a
per-execution budget, and it is exactly why §5's separate run-level ceiling
exists. The budget bounds *repair*; it does not bound *composition*.

### 3.4 Step identity

`step_id` is `f"{run_id}-s{execution_index}"`. `execution_index` is a
controller-owned integer starting at 1.

**`step_id` increments once per authorized execution, never per attempt.** A
retry of execution 2 stays inside execution 2's attempt sequence and keeps
`-s2`; it never becomes `-s3`. This is the single most load-bearing identity
rule in the milestone, because a step id that moved on retry would make the
journal describe a composed run where a retried one actually happened.

### 3.5 Model output cannot control execution or step identity

`execution_index` derives from nothing external: no wall clock, no UUID, no
randomness, no ambient state, and no model output. `step_id` is a pure function
of `run_id` and that counter. `execution_id` is a hash whose only
model-influenced input is an argument set that three gates have already
accepted.

There is no field on `ModelResponse`, `RawToolCall` or `ExecutionComplete`
through which a step id, an execution id, an attempt number, a state, a budget
or a ceiling can be expressed — all three types set `extra="forbid"`, so an
envelope carrying a smuggled control field is rejected as malformed rather than
partially honoured.

### 3.6 When the controller asks for another execution

**Unconditionally, after every verified execution in a fresh run.** The ceiling
is deliberately *not* consulted at the boundary.

The rejected alternative was to stop asking once capacity is gone and terminate
successfully. That would report a run as complete when the model may have had
further work — conflating *"the ceiling was reached"* with *"the task is
finished"*. Those are exactly the two facts this milestone exists to keep
apart, and reporting truncation as success is a silent-truncation failure. So
the question is always asked, and a request beyond the ceiling is refused
loudly (§5).

### 3.7 How the completion signal reaches terminal routing

The structured channel carries two shapes, discriminated by a reserved
capability name:

```python
COMPLETION_TOOL = "execution.complete"


class ExecutionComplete(_Strict):
    tool: Literal["execution.complete"]
    arguments: dict[str, Any] = Field(default_factory=dict)  # must be empty
```

`parse_candidate` — one parser, not two — dispatches on
`payload.get("tool") == COMPLETION_TOOL` *before* a `RawToolCall` is
constructed, so a completion can never become a proposal. `registry.admit`
refuses the reserved name (`capability_name_is_reserved`), so it can never
resolve to a capability either. A completion carrying arguments is a *malformed
completion*, not a proposal in disguise.

**Why a reserved tool name rather than a `type` tag.** The originally designed
`{"type": "execution_complete"}` envelope was correct in the abstract and
unreachable in practice: the production adapter builds `structured_output`
from `message.tool_calls`, so it can emit `{"tool": ..., "arguments": ...}` and
nothing else. A completion contract that only the test double could express
would have been a contract the deployed system does not have. The reserved name
is expressible over the wire, which is the property that matters.

**Absence is unchanged.** `structured_output` that is `None`, empty, non-JSON,
or not a JSON object still yields `TOOL_CALL_MALFORMED`. Silence is never
success. The Milestone 9 invariant and its named test are untouched.

---

## 4. Completion authority

> **A completion signal is a model-level terminal *request*, not terminal
> *authority*.**

The model may ask that the run end. Only the controller decides whether it may.
Three rules follow, and each closes a specific laundering path:

**4.1 Completion at a valid composition boundary may lead to `TERMINAL`.**
`PARSE → TERMINAL`, status `succeeded`, reporting `last_result` and
`last_execution_attempts` — the result and attempt count of the last execution
the controller actually verified, never a number the model supplied.

**4.2 Completion while an outstanding rejection remains unresolved is
refused.** The controller asks two different questions and they admit different
answers. After a rejection it asks *"repair this proposal"*; after a verified
execution it asks *"anything else?"*. Only the second admits a completion.

Without this rule a model told its proposal was denied could answer "complete"
and the run would report `succeeded` — the model deciding a run's outcome,
which is the one thing every gate in the pipeline exists to prevent. The
refusal therefore terminates the run on the error that was actually
outstanding, not on a new error about the completion: the failure is the
proposal nobody repaired, and saying "I am finished" did not create a second,
different problem.

The condition is `feedback is not None`, which holds exactly when a rejection
in the current execution has not yet been repaired.

**4.3 Completion after execution-ceiling exhaustion does not convert exhaustion
into success.** This needs stating precisely, because the naive reading is
wrong in a way that matters.

The ceiling gates *execution requests*. It does not gate termination. So when
the ceiling is full and the model sends a completion, no denial has occurred —
nothing was requested, so nothing was refused — and the run terminates
`succeeded`, reporting exactly the executions that were verified. That is not
laundering; it is the honest outcome of a run that used its capacity and then
finished.

Exhaustion becomes a *failure* only when the model proposes further work with
no slot left (§5). And a completion cannot reverse that failure, by two
independent mechanisms: `POLICY_DENIED` is not in `RETRYABLE_CODES`, so the run
is terminal before another model turn exists; and were it ever made retryable,
rule 4.2 would refuse the completion because the denial would be outstanding.

**4.4 Completion never bypasses an outstanding controller obligation.** 4.2 and
4.3 are the two instances that exist today. The general rule is stated
separately so that a future obligation inherits it by default rather than by
someone remembering to add a branch.

---

## 5. The execution ceiling

`max_executions` is a **run-level composition ceiling**, constitutionally
distinct from `max_attempts`. Neither is derived from, decremented by, or
substituted for the other.

| | question it answers | scope | default |
|---|---|---|---|
| `max_attempts` | how many attempts may *this execution* receive? | execution | 3 |
| `max_executions` | how many independent executions may *this run* contain? | run | 1 |

They are validated independently (`max_attempts < 1` and `max_executions < 1`
are separate `ValueError`s, neither checked against the other): a run with one
execution and three attempts is as legitimate as one with three executions and
one attempt.

**Why the default is 1.** It reproduces the pre-M10 contract exactly. A run
composes one execution unless a deployment asks for more; composition is
opt-in, in the same spirit as the separate registry builders M8 and M9 added.

**Where it is checked.** After `PARSE`, before `VALIDATE`. A proposal arriving
with `execution_index > max_executions` is refused at the authority boundary,
so it never reaches `VALIDATE`, `AUTHORIZE`, `POLICY_CHECK` or any executor.
The refusal is `POLICY_DENIED`, which is not retryable, so it consumes no
retry budget and moves no attempt counter — the ceiling is not a failure of
*this* execution, it is the run's capacity running out. The run terminates
`failed` with an auditable `execution_ceiling_exhausted` event.

**Slots are consumed by authorization, not by attempts and not by resumption.**
See §7.4.

---

## 6. Controller authority

> **The model may state; only the controller may decide.**

Every model output is an untrusted request, evaluated against state the model
cannot observe or influence:

* **model proposals are untrusted requests** — parsed, schema-validated,
  authorized, policy-checked, executed and verified before anything happens,
  with any gate able to end the run;
* **the reserved completion signal is an untrusted request** — it is validated
  by the same parser at the same boundary, and §4 governs whether it is
  honoured;
* **model-provided identity is never authoritative** — there is no channel
  through which a model can name a run, step, execution, attempt, state or
  budget;
* **the controller owns execution identity** — `derive_execution_id` over
  controller-owned position and post-gate arguments;
* **the controller owns step identity** — a private counter (§3.4);
* **the controller owns authorization** — the registry, the grants, the digest,
  and the gates, re-run from scratch on every path including recovery;
* **the controller owns terminality** — `Run.advance` consults `TRANSITIONS`
  and raises `IllegalStateTransitionError` otherwise; `TERMINAL` has no
  outgoing edges.

**No model output may directly cause successful termination.** In a fresh run,
`succeeded` requires *both* that the controller verified every execution it
counted *and* that the controller chose to honour an affirmative completion. In
a recovered run, `succeeded` requires the restored execution to verify, and no
model output participates at all — the adapter is never called.

---

## 7. The recovery boundary

**Recovery is the restoration and completion of the already-authorized
execution at the interruption boundary.** It is not a new run, not a new
execution, and not a continuation of orchestration.

### 7.1 What is persisted

The journal is the whole of the durable state. Five record types:

| record | carries |
|---|---|
| `RunStarted` | `run_id`, `max_attempts`, **`max_executions`**, `schema_version` |
| `ExecutionAuthorized` | `run_id`, `step_id`, `attempt`, `tool`, canonical `arguments`, `execution_id`, `side_effect_free`, `capability_digest` |
| `ExecutionCompleted` | `run_id`, `execution_id`, `status`, `reason` |
| `OperatorDecisionRecorded` | `decision_sequence`, `action`, `plan_id`, `expected_execution_id`, `reason_code` |
| `RunTerminal` | `status`, `code`, `attempts` |

The conversation is deliberately **not** persisted, which is why `recover()`
takes `messages` from its caller.

### 7.2 What is reconstructed rather than trusted

Nothing in the journal is believed on its own authority. `plan_recovery`
re-derives everything against live authority, and `_revalidate_recovery` then
does it *again* after the operator decision is durable — because an approval is
a statement about a moment, and the moment ends the instant the decision is
recorded.

Reconstructed: the `ToolSpec` from the live registry; the arguments
re-validated against that tool's *current* schema; both gates re-run against
the live `RunContext`; the capability digest re-computed and compared; the
execution identity re-derived and compared against both the journal and the
operator's `expected_execution_id`.

### 7.3 What is reused

| reused | source | failure if it disagrees |
|---|---|---|
| execution identity | journal, re-derived | `execution_identity_mismatch` |
| step identity | journal (`_ResumeSeed.step_id`) | `execution_position_changed` |
| proposal: tool + arguments | journal, re-validated | `tool_changed` / `arguments_changed` |
| attempt number | journal (`_ResumeSeed.attempt`) | `execution_position_changed` |
| the write-ahead authorization | the record already on disk | — |

A resume writes **no second `ExecutionAuthorized`**. The record already on disk
*is* the authorization; writing another would forge one the controller never
made, and recovery would then reject its own journal for a duplicate.

### 7.4 Slots, and what recovery does not consume

> **Resuming an already-authorized execution does not consume a second
> execution slot for that same execution.**

A recovered `-s2` remains `-s2`. Recovery does not transform it into a
newly-authorized `-s3`. This follows structurally rather than by a guard:
`_loop` takes its `step_id` from the seed, `execution_index` is never
incremented on the resumed path, and the composition boundary is not reached.

### 7.5 What recovery does not manufacture

> **Recovery must not manufacture a new model generation after the recovered
> execution completes.**

This is a semantic boundary, not a test-specific behaviour. Concretely: a
resumed run that verifies terminates `RESPOND → TERMINAL`, and the model
adapter is called **zero** times across the whole recovery.

The states `RECEIVE → CLASSIFY → GENERATE` *are* walked when `recover()` enters
the loop, because the run really did pass through them before it crashed — the
same run is continuing, not a new one skipping gates. `_loop` with a seed makes
no model call there. The invariant is about the *second* generation: a fresh
run re-enters `GENERATE` after `RESPOND`; a recovered run does not.

A resumed execution that *fails* and still has attempt budget continues into an
ordinary retry, which does call the model — that is repair of the restored
execution, not extension of the run, and it stays inside the restored
execution's step id and attempt sequence.

### 7.6 Execution count on the recovered path

`RunOutcome.executions` counts the executions **this invocation verified**. A
resume reports 1.

The run-level total is not restored, and this is a deliberate refusal rather
than an oversight: **the durable record set cannot express it.**
`ExecutionCompleted(status="succeeded")` is written immediately after the
executor returns and *before* `VERIFY` runs, so the journal records that the
physical call finished, not that the controller accepted its result. A count
derived from those records would therefore include executions that failed
verification — it would be a fabricated number wearing the name of a real one.

Reporting a per-invocation count with a stated meaning is honest; reconstructing
a run total from evidence that cannot support it is not. Closing this properly
needs a new durable fact (a verification record, or a status written at
`RESPOND`); that is recorded as gap **G-VERIFY** in §11 and is deliberately not
invented here.

Nothing depends on the missing total today: a resumed run does not compose, so
no ceiling decision consults it.

### 7.7 Journal facts that establish the recovery boundary

The interruption boundary is established entirely by evidence, never by
inference:

* **an execution is pending** iff an `ExecutionAuthorized` exists with no
  matching `ExecutionCompleted`;
* **more than one pending execution** → `journal_multiple_pending_executions`.
  The controller authorizes one execution at a time, so two pending records
  describe a run this controller could not have produced;
* **a completion with no authorization** → forged result,
  `journal_completion_without_authorization`;
* **duplicates** → `journal_duplicate_authorization`,
  `journal_duplicate_completion`, `journal_duplicate_run_started`;
* **anything after a `RunTerminal`** → `journal_record_after_terminal`;
* **the disposition of a pending execution** is `execution_pending_repeatable`
  when the authorization recorded `side_effect_free`, else `execution_unknown`.
  Resume is offered only when the capability is `re_executable`.

---

## 8. Persisted ceiling authority

> **The execution ceiling persisted in `RunStarted` is authoritative for the
> lifetime of the run, including recovery and replay.**

Recovery and replay must not silently substitute a new default, the current
configuration, a different `max_executions`, or `max_attempts` for the ceiling
under which the run originally began.

**The defined failure:** if `RunStarted.max_executions != RunContext.max_executions`,
`_validate_sequence` raises `RecoveryError("journal_execution_ceiling_mismatch")`.
It is raised, never repaired: the ceiling is not reconciled, defaulted, widened,
narrowed, or taken from whichever side looks more plausible.

This is deliberately symmetric with the existing
`journal_budget_mismatch` for `max_attempts`, and it sits in
`_validate_sequence`, which both `plan_recovery` and `replay` call — so one
implementation serves both paths and neither can drift from the other.

A journal predating the field validates as `max_executions = 1` via the record
default, which is the correct reading: a run written before composition existed
composed one execution.

---

## 9. Replay

Replay reconstructs a run's observable shape from its journal. It takes no
executor, no adapter and no transport; it reads the registry only to
re-validate records, never to reach `ToolSpec.executor`. **Replay executes
nothing**, and a malicious journal has nothing here to trigger.

**What constitutes a completed execution** — for replay and for recovery
alike — is an `ExecutionAuthorized` paired with an `ExecutionCompleted` for the
same `execution_id`. That pairing is the durable fact. It states that the
physical call finished; it does *not* state that verification accepted the
result (§7.6).

**How duplicate execution is prevented:** replay never executes, so the
question is really whether *recovery* can re-run something already done. It
cannot: a paired authorization is not pending, only pending executions are
resume candidates, a `RunTerminal` makes the whole run disposition `terminal`
with no available actions, and terminality is immutable
(`journal_record_after_terminal`).

**Identity under replay** is read, never re-assigned. `execution_ids` are
reported in journal order. Replay assigns no step ids and no execution ids of
its own; it has no counter.

**The persisted ceiling participates in replay validation** through
`_validate_sequence` (§8) — replay calls `plan_recovery` first precisely so
that replaying an untrusted journal is not a way to bypass the checks recovery
applies.

**Contradictory or incomplete durable state** fails closed with the named
`RecoveryError` slugs in §7.7. Replay raises them rather than reconstructing a
best-effort trace, because a partial reconstruction of a journal that cannot be
validated would be a story rather than evidence.

**Known divergence, deferred:** replay's state reconstruction is *not* faithful
under composition. It appends `PARSE…EXECUTE` per authorization and
`VERIFY`/`FEEDBACK` per completion, so a multi-execution journal yields
`VERIFY → PARSE`, a transition absent from `TRANSITIONS`. The controller
actually walks `VERIFY → RESPOND → GENERATE → PARSE`. This is recorded as gap
**G-REPLAY** in §11, is observational rather than a security hole, and is not
patched here because §12's contract-first rule sequences it after this
document.

---

## 10. Boundary-condition routing

Two tables over the same eleven cases: the first is control flow, the second is
accounting. "Fresh" means `seed is None`.

### 10.1 Routing

| # | input / event | current state | controller decision | resulting states | terminal result |
|---|---|---|---|---|---|
| 1 | valid proposal, slot available | PARSE | accept; run every gate | VALIDATE → AUTHORIZE → POLICY_CHECK → EXECUTE → VERIFY → RESPOND → GENERATE | non-terminal |
| 2 | malformed output (absent / non-JSON / non-object / unknown shape) | PARSE | `TOOL_CALL_MALFORMED`, retryable | FEEDBACK → RETRY → GENERATE, or FEEDBACK → TERMINAL | non-terminal, or `failed / RETRY_EXHAUSTED` |
| 3 | rejected proposal (schema / tool / grant / policy) | VALIDATE, AUTHORIZE or POLICY_CHECK | reject with its own code | FEEDBACK → RETRY → GENERATE (`SCHEMA_INVALID` only) or FEEDBACK → TERMINAL | non-terminal, or `failed / <code>` |
| 4 | completion while a rejection is outstanding | PARSE | **refuse** (§4.2); terminate on the *outstanding* error | FEEDBACK → TERMINAL | `failed / <outstanding code>` |
| 5 | executor raised | EXECUTE | record completion `failed`; consult retryability **and** re-executability | FEEDBACK → RETRY → GENERATE, or FEEDBACK → TERMINAL | non-terminal, or `failed` |
| 6 | retry succeeds at attempt k+1 | PARSE (same step id) | accept; same slot, new attempt | VALIDATE → … → RESPOND → GENERATE | non-terminal |
| 7 | retry exhausted (`attempt == max_attempts`) | FEEDBACK | no budget | TERMINAL | `failed / RETRY_EXHAUSTED` |
| 8 | proposal with `execution_index > max_executions` | PARSE | `POLICY_DENIED` before VALIDATE (§5) | FEEDBACK → TERMINAL | `failed / POLICY_DENIED` |
| 9 | completion with the ceiling full | PARSE | honour it — the ceiling gates requests, not termination (§4.3) | TERMINAL | `succeeded` |
| 10 | recovery: resume of a pending execution | PARSE (seeded) | restore; re-validate everything; run the ordinary gates | VALIDATE → AUTHORIZE → POLICY_CHECK → EXECUTE → VERIFY → RESPOND → TERMINAL | `succeeded` |
| 11 | replay of an already-completed execution | — (no machine) | reconstruct only | reconstructed trace | none — replay has no terminal authority |

### 10.2 Accounting

| # | journal records written | events recorded | attempt changes? | execution count changes? | another model generation? |
|---|---|---|---|---|---|
| 1 | `ExecutionAuthorized`, `ExecutionCompleted(succeeded)` | `candidate_parsed`, `execution_started`, `execution_succeeded`, `execution_finished` | no (resets to 1 at the boundary) | **+1** | **yes** — the composition boundary |
| 2 | none; `RunTerminal` if exhausted | `model_output_received`, then `retry` or `terminal` | +1 on retry | no | yes, while budget remains |
| 3 | none; `RunTerminal` if terminal | `tool_not_found` / `schema_rejected` / `authorization_rejected` / `policy_rejected` | +1 on retry (`SCHEMA_INVALID`) | no | only for the retryable code |
| 4 | `RunTerminal(failed, <outstanding>)` | `completion_rejected_during_repair`, `terminal` | no | no | **no** |
| 5 | `ExecutionAuthorized`, `ExecutionCompleted(failed, reason)` | `execution_failed`, then `retry` / `retry_withheld` / `terminal` | +1 on retry | no | only if retried |
| 6 | a *second* `ExecutionAuthorized` at the same `step_id`, attempt k+1, then `ExecutionCompleted(succeeded)` | as case 1 | already incremented | **+1** (the execution, counted once) | yes |
| 7 | `RunTerminal(failed, RETRY_EXHAUSTED, attempts)` | `terminal` | no | no | **no** |
| 8 | `RunTerminal(failed, POLICY_DENIED, attempts=1)` | `execution_ceiling_exhausted`, `terminal` | **no** — non-retryable | no | **no** |
| 9 | `RunTerminal(succeeded, attempts=last_execution_attempts)` | `execution_complete_declared`, `terminal` | no | no | **no** |
| 10 | `OperatorDecisionRecorded`, `ExecutionCompleted`, `RunTerminal(succeeded)` — **no second `ExecutionAuthorized`** | `recovery_planned`, `operator_decision_recorded`, `recovery_revalidated`, `recovery_resumed`, `execution_finished`, `terminal` | no — the crashed attempt is restored | +1 for this invocation (§7.6) | **no** — the recovery boundary |
| 11 | none — replay writes nothing | none — replay has no recorder | no | no | **no** — replay never calls a model |

---

## 11. Invariants

Numbered so tests can cite them.

**I1 — single choke point.** Every state change passes through `Run.advance`
and is a member of `TRANSITIONS`. `TERMINAL` has no outgoing edges.

**I2 — step identity.** `step_id == f"{run_id}-s{execution_index}"`;
`execution_index` increments exactly once per verified execution, and never on
an attempt, rejection, failure or operator decision.

**I3 — attempt identity.** `tool_call_id == f"{step_id}-a{attempt}"`;
`1 <= attempt <= max_attempts`; `attempt` resets to 1 only at a composition
boundary.

**I4 — execution identity.** `execution_id ==
derive_execution_id(run_id, step_id, attempt, tool, canonical_args)`, computed
after all gates and before any physical effect. No model-supplied value names
an identity.

**I5 — no model-caused success.** A fresh run reaches `succeeded` only via an
affirmative completion the controller honoured at a composition boundary. A
recovered run reaches `succeeded` with the adapter never called.

**I6 — completion is not a repair.** A completion arriving while
`feedback is not None` is refused, and the run terminates on the outstanding
error code.

**I7 — the ceiling gates requests, not termination.** `max_executions` refuses
proposals beyond capacity and never refuses, delays or converts a completion.

**I8 — recovery reuses identity.** `(step_id, attempt, tool, arguments,
execution_id)` all come from the journal, are all re-derived, and any
disagreement refuses the recovery by a named slug.

**I9 — recovery authorizes nothing new.** A resume writes no second
`ExecutionAuthorized`.

**I10 — recovery manufactures no generation.** After the recovered execution
verifies, the run terminates; no `GENERATE` follows `RESPOND`, and the adapter
call count for a first-attempt resume is 0.

**I11 — no slot is double-consumed.** A recovered `-s2` remains `-s2`.

**I12 — the persisted ceiling is authoritative.** `RunStarted.max_executions`
must equal `RunContext.max_executions` on every recovery and replay, else
`journal_execution_ceiling_mismatch`.

**I13 — replay executes nothing** and reaches no `ToolSpec.executor`.

**I14 — determinism.** Identity and ordering derive only from controller-owned
counters, content hashes and recorded sequence numbers: no clock, no
randomness, no set-iteration order, no filesystem enumeration.

**I15 — semantic independence.** Each execution's classification,
authorization, digest, disposition and retry gate are read per-`ToolSpec` and
per-record. No run-level aggregate of any semantic axis exists.

---

## 12. Compatibility boundaries and known gaps

### Explicit boundaries (intentional, permanent until revisited)

**B1 — recovery does not compose.** §1 and §7.5. This is the M10 boundary, and
it is a decision rather than a limitation. Milestone 6's §22.8 deviation
deferred exactly this, and M10 keeps it deferred *for the stated semantic
reason*, not for convenience.

**B2 — recovery reports a per-invocation execution count.** §7.6.

**B3 — enforced execution deadlines.** `ToolSpec.timeout_seconds` remains
declarative. M8's debt, carried forward unchanged and still not made to look
enforced.

### Gaps (contract exceeds implementation; to be closed, not redefined)

**G-VERIFY — verified success is not a durable fact.**
`ExecutionCompleted(succeeded)` is written before `VERIFY` runs, so the journal
cannot distinguish "the executor returned" from "the controller accepted the
result". Consequence: the run-level composed-execution count is not
reconstructible (§7.6), and a journal whose last execution failed verification
looks, durably, like one that succeeded until the following authorization
record disambiguates it.

**G-REPLAY — replay reconstructs an illegal transition under composition.**
§9. `VERIFY → PARSE` is absent from `TRANSITIONS`.

**G-COUNTS — two fields named for executions mean different things.**
`RunOutcome.executions` counts executions *verified*;
`ReplayResult.executions_completed` counts every `ExecutionCompleted` record,
*including failures*. Before composition nobody could compare them; now they
can be compared and will disagree.

**G-AUDIT — `run_created` records `max_attempts` only.** The composition
ceiling is durable in `RunStarted` but absent from the in-memory event stream,
so an audit of events alone cannot say what capacity a run held.

**G-PLAN — recovery plans describe only the latest execution** when none is
pending (Phase 0 gap G4). Defensible for a resume decision, incomplete as a
description of a composed run.

---

## 13. Rejected alternatives

**Treating "no tool call proposed" as run completion.** It inverts a named
fail-closed test, makes one wire value mean two different things depending on
position, and makes model silence indistinguishable from task success.

**A `has_more` / `continue_execution` / `done` boolean on `ModelResponse`.** A
control field on an untrusted channel. `ExecutionComplete` is not this: it is a
proposal-shaped statement the parser validates and §4 governs, not a boolean
the controller obeys.

**A `{"type": "execution_complete"}` envelope.** Correct in the abstract,
unreachable through the production adapter (§3.7).

**A caller-supplied plan or step list.** That is a workflow. It would move the
decision of *which capabilities run* from the model's proposals to a static
structure. Out of scope.

**A scheduler, execution queue, orchestrator, DAG, `ExecutionManager`,
`WorkflowManager`, `Pipeline` or `CompositionManager`.** Not needed and not
built. Composition needs the existing loop to be allowed to go round again, not
a manager for a list of operations.

**`while True` with an implicit termination heuristic.** The first rejected
alternative wearing different clothes.

**Stopping the composition question once the ceiling is full.** §3.6. It
reports truncation as success.

**Making `RESPOND → GENERATE` unconditional.** The edge exists; taking it is
conditional on a fresh run having verified an execution. A recovered run never
takes it (§7.5).

---

## 14. Assumptions

Unchanged from M5–M9: `fsync` durability, append ordering, advisory `flock`,
POSIX semantics, `O_NOFOLLOW` and `O_APPEND` honoured by the filesystem,
trustworthy configured roots, and no in-process circumvention of the registry.

Still unproven, and stated as such: that any deployed LocalAI instance
populates `choices[].finish_reason` (which is why the completion contract does
not depend on it), and that a model will comply with an affirmative completion
signal at all (which is why §5's ceiling is required rather than optional).

Not claimed anywhere: exactly-once, atomic, transactional, durable-across-media
-failure, rollback-safe, crash-safe or linearizable.
