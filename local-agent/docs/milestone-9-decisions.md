# Milestone 9 — First Non-Re-Executable Mutation

Milestone 8 gave the system a real side effect that was safe to repeat.
Milestone 9 asks a harder question, and it is a question about the
architecture rather than about a feature:

> Can this system represent an execution that **may** have happened, that
> **must not** be repeated, without collapsing "we do not know" into either
> "it failed" or "it succeeded" — and still let an operator close the run?

This document is written before the implementation, as §6 requires, and is
updated only with measured results.

## 0. The four axes, and why they must not be substituted for one another

The milestone's constitutional rule is that six related facts stay six facts:

| Axis | Question it answers | Owner |
|---|---|---|
| `side_effect_free` | Could anything have happened? | `ToolSpec`, derived from `SideEffect` |
| `re_executable` | If it may have happened, is repeating safe? | `ToolSpec`, derived from `SideEffect` |
| `SideEffect` | What behavioural class is this? | the capability's declaration |
| `execution_identity` | Which exact attempt was this? | `derive_execution_id` |
| journal evidence | What does the system actually *know*? | the durable records |
| recovery disposition | What conclusion is *justified*? | `plan_recovery` |

They correlate for every capability built so far, which is exactly the danger:
`workspace.read` is `NONE` (free, re-executable) and `workspace.write` is
`IDEMPOTENT` (not free, re-executable). No capability has yet inhabited the
fourth corner — not free, **not** re-executable — so no test has ever proven
that the axes are genuinely separate rather than accidentally aligned.

That is the whole point of this milestone. The new capability's only job is to
occupy that corner and see whether anything breaks.

## 1. Phase 0 findings: what the architecture already does

Tracing the call graph before writing anything turned up a result worth
stating plainly, because it changes what this milestone *is*.

**The architecture already appears to represent the M9 state.** Three
mechanisms, all built for earlier milestones, combine to produce it:

* `controller.py`'s retry gate is `error.retryable AND (invoked is None OR
  invoked.re_executable) AND budget`. A `MUTATING` capability that reaches the
  executor and then fails is already refused a second attempt — Milestone 7
  built this, and Milestone 8's `IDEMPOTENT` writer exercised only the
  permissive branch of it.
* `recovery.plan_recovery` derives the disposition from
  `authorization.side_effect_free` (the **evidence** axis) and derives the
  availability of `resume` from `spec.re_executable` (the **safety** axis).
  Milestone 8 separated these after finding them conflated. A `MUTATING`
  execution with no completion record therefore lands on `execution_unknown`
  and is offered no resume.
* `recovery._available_actions` returns `_TERMINATING_ACTIONS +
  _PASSIVE_ACTIONS` for every non-terminal disposition, so `abort` and
  `terminalize` remain available even when `resume` is withheld. The operator
  escape hatch §13 demands already exists, and `Controller.recover` reaches it
  without touching an executor.

So M9's honest shape is **verification, not construction**. The prediction is
that no new control-plane machinery is required, and the milestone's value is
in proving that prediction wrong or right with a capability that actually
inhabits the corner. Predictions of this kind have been wrong twice in this
project already — Milestone 8 found that Milestone 7 had fixed one of two
paths sharing a premise — so the prediction is not the finding. The tests are.

If an existing primitive turns out to be insufficient, §2 requires documenting
exactly why before changing it. Any such finding is recorded in §11 below.

## 2. Capability selection

§5 forbids assuming the capability in advance and requires selecting the
*smallest justified* mutation the current architecture supports. Working from
the architecture rather than from a wish list:

**Where can an observable effect even live?** The system holds exactly three
physical grants: the workspace filesystem (read via `workspace_fs.py`, write
via `workspace_write.py`), the durable journal (`journal.py`), and the network
(`transports/http.py`). The journal is controller-owned and §2 forbids a second
persistence mechanism, so it cannot be a capability's target. Network mutation
is forbidden outright. Every other medium — a database, a queue, a subprocess,
an external API — is on §2's prohibition list.

**Therefore the medium must be the workspace filesystem**, and §2 additionally
forbids "new filesystem authority" and "broader filesystem access". That
eliminates `unlink`, `rename`, `mkdir` and `chmod`: each is a syscall the
package has never held, and reaching for one would expand authority to obtain
a semantic property, which is precisely the move this milestone is testing
against.

So the real question narrows to: **what is the smallest non-re-executable
operation expressible with the syscalls already granted** — `os.open` with
flags, `os.write`, `os.fsync`, `os.close` — inside the existing containment?

### Candidates considered and rejected

**Exclusive creation (`O_EXCL`).** "Create this artifact; fail if it exists."
Rejected because it does not satisfy the formal criterion. `R(S)` creates the
file; `R(S₁)` fails and leaves the file exactly as it was. The *reported
outcome* differs but the externally observable state does not, so this is
at-most-once creation — closer to `IDEMPOTENT` than to `MUTATING`, and
selecting it would mean declaring `MUTATING` for a capability whose behaviour
does not earn it. §5 explicitly forbids choosing a classification for
convenience.

**Consume / mark-used / delete-after-read.** Genuinely non-re-executable, and
semantically the most honest example of the class. Rejected because it needs
`os.unlink` or `os.rename` — new filesystem authority, banned by §2.

**A counter, ticket or sequence allocator.** Requires somewhere to keep the
counter. Any durable home is either the journal (forbidden) or a new
persistence system (forbidden), and an in-memory counter has no externally
observable state at all, which fails the criterion by definition.

### Selected: `workspace.append`

Appending bytes to an existing file satisfies the formal criterion directly and
is reachable with **zero new authority**. §5 warns against choosing append
merely because it is obviously non-idempotent, so the justification is
deliberately not that:

`_APPEND_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW` is **strictly
fewer flags** than Milestone 8's `os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
os.O_NOFOLLOW`. It introduces no syscall the package did not already make, no
import beyond `os`, and no containment logic that does not already exist. It
is the *minimum possible perturbation* of an already-audited primitive that
lands in the fourth corner. That, not its non-idempotence, is why it wins.

Dropping `O_CREAT` is what keeps this from becoming a filesystem-semantics
milestone. The destination must already exist, so there is no creation mode,
no permission question, no `created` field, and no truncation. The capability
adds bytes to an artifact some earlier authorized step produced, and does
nothing else.

### The mandated append analysis

§5 requires each of these to be addressed explicitly. Each was measured before
the capability was chosen, not asserted afterwards.

**Repeated invocation.** The point of the milestone. Measured: seeding a file
with `seed\n` and applying an identical request twice yields
`seed\nentry\nentry\n`, where once yields `seed\nentry\n`. The difference is
file content, which is squarely inside the declared effect rather than
metadata — this is the distinction Milestone 8's `IDEMPOTENT` claim turned on,
and here it falls the other way.

**File offsets.** This code never computes an offset. Under `O_APPEND` the
kernel positions the write at end-of-file as part of the same operation. That
is why `O_APPEND` rather than `seek`-then-`write`: the latter is two syscalls
with a race between them, and the same reasoning that made `O_NOFOLLOW`
preferable to a pre-flight symlink check applies again.

**Ordering and concurrency.** Measured: two descriptors open on the same file,
written interleaved, produce `AAA\nBBB\nCCC\n` — no overwrite, no lost write.
This is a POSIX guarantee for local filesystems and is recorded in §7 as an
**assumption**, not a proof: NFS is the well-known counterexample. Concurrency
*within* this controller is bounded by the journal's `flock` as it was in
Milestone 8; other processes are outside the model, unchanged.

**Buffering.** None. The module calls `os.write` on a raw descriptor with no
Python-level buffering layer between the payload and the syscall, which is
verifiable from the module's AST rather than from this sentence.

**Partial writes.** `os.write` may return fewer bytes than requested. Measured
at the ceiling (8,192 bytes) it returned the full count, but "did not happen
here" is not "cannot happen", so the return value is checked. A short write is
**not** completed by looping. It is reported as `fs_append_incomplete`, because
a partial append is a genuine partial effect: bytes are already in the file and
no repetition can fix that without duplicating them. This is the M9 state made
physical rather than a defect to paper over, and the refusal is non-retryable
for the same reason the whole capability is.

**Crash behaviour and durability.** The payload is `fsync`ed before the call
returns. A crash before the `fsync` may leave the append invisible, complete,
or partial — the containing directory is not synced, exactly as in Milestone 8,
and no stronger claim is made.

**Is the declared effect bounded?** Yes: at most `max_file_append_bytes`
encoded bytes are added to exactly one existing regular file beneath exactly
one authorized root. Nothing is created, deleted, renamed, moved, truncated or
re-permissioned.

**Would M9 accidentally become a filesystem-semantics milestone?** That is the
real risk, and the mitigations are structural: no `O_CREAT` removes the
creation question, no `O_TRUNC` removes the replacement question, requiring an
existing regular file removes the file-type question to a single reused check,
and containment is Milestone 2's helper unchanged. What remains is one flag and
one classification, which is the milestone's actual subject.

## 3. Capability contract

| Field | Value |
|---|---|
| name | `workspace.append` |
| `args_schema` | `WorkspaceAppendArgs` (`root_id`, `path`, `content`) |
| `result_schema` | `WorkspaceAppendResult` (`status`, `root_id`, `path`, `bytes_appended`) |
| `requires_authorization` | `True` |
| `destructive` | `False` |
| `side_effect` | `SideEffect.MUTATING` |
| `side_effect_free` | `False` (derived) |
| `re_executable` | `False` (derived) |
| `timeout_seconds` | `5.0` (declared and recorded; see §9) |

**Intent.** Add exactly these bytes to the end of exactly this existing file
beneath one authorized root.

**`destructive` is `False`, and that is not a loophole.** The flag means "does
this remove or overwrite something that existed" — appending removes nothing
and overwrites nothing. `MUTATING` and `destructive` are different axes, which
is the milestone's own thesis applied to two more fields, and admission
enforces the one combination that would be incoherent (`destructive=True` with
`requires_authorization=False`).

**Execution identity** is unchanged: `sha256(run_id, step_id, attempt, tool,
canonical arguments)`. Two appends of the same content to the same path in the
same run are different executions because `attempt` differs — which matters
more here than anywhere previously, since for this capability those two
executions leave genuinely different state.

**Capability digest** participation is unchanged: both schemas plus the
declared properties, recorded on `ExecutionAuthorized`. Because `side_effect`
feeds the digest, reclassifying this capability after an authorization is
recorded is detected by recovery.

**Journal behaviour** is unchanged and no new record type is introduced. The
write-ahead `ExecutionAuthorized` carries `side_effect_free=False`, which is
what makes the crash window representable at all.

**Model-visible boundary.** The model sees the tool name, a one-line
description written in trusted wiring, and the argument JSON schema. It does
not see `side_effect`, `re_executable`, `side_effect_free`, the digest, the
execution id, the timeout, or any recovery vocabulary. A withheld retry still
reports `RETRY_EXHAUSTED`.

**Executor isolation** is unchanged: no `RunContext`, no gate, no registry, no
journal, no model, no operator surface. The module's grant is `{"os"}`.

## 4. Why `MUTATING`

`NONE` is false on its face: bytes reach a disk and a subsequent read observes
them, so "nothing happened" is not a description of this capability. Declaring
`NONE` would make an ambiguous crash report `execution_pending_repeatable`,
which is the exact failure the milestone exists to prevent.

`IDEMPOTENT` is the interesting rejection, because Milestone 8's writer is
`IDEMPOTENT` and this capability differs from it by one flag. The Milestone 8
claim was bounded: *idempotent with respect to the destination artifact's
existence and content*. Under `O_TRUNC` the second identical request produces
the same content as the first, so that bound holds. Under `O_APPEND` it fails
against its own definition — the content after two identical requests is
demonstrably not the content after one. The classification therefore follows
from behaviour measured against a definition already written down, which is
the discipline §5 asks for.

`MUTATING` is also the enum's default, so this capability is the first that
does not have to override it.

## 5. Why repeating is unsafe — the concrete example §6.3 requires

```
S   = file contains "seed\n"
R   = append "entry\n" to that path

R(S)  = S₁ = "seed\nentry\n"
R(S₁) = S₂ = "seed\nentry\nentry\n"

S₂ ≠ S₁
```

The difference is the file's content, which is the capability's declared
effect. Measured, not argued.

**The duplicate-effect hazard.** Suppose the executor appends the bytes and
then the run fails with a retryable error — a result that fails validation,
say, or a partial write. The bytes are already in the file. A retry would
append them again, so the run's *third* attempt would leave three copies of a
payload the model asked to add once. The controller cannot distinguish "the
append did not happen" from "the append happened and something after it went
wrong", so the only safe policy is to never repeat automatically. That is
exactly what `re_executable=False` instructs, and Milestone 7 measured the
opposite outcome — three physical effects for a budget of three — on the tree
before the capability gate existed.

## 6. Recovery semantics: three states, not a boolean

§6.5 requires these to stay distinct, and the architecture already has three
different representations for them:

| State | Journal evidence | Disposition | Resume offered |
|---|---|---|---|
| definitely did not execute | no `ExecutionAuthorized` | `no_execution_authorized` | n/a — nothing to resume |
| may have executed | `ExecutionAuthorized`, no `ExecutionCompleted` | `execution_unknown` | **no** (`re_executable=False`) |
| definitely completed | `ExecutionAuthorized` + `ExecutionCompleted` | `execution_completed` | no (result never retained) |

The middle row is the milestone. It is reached only by a **crash** between the
executor call and the completion record, because a clean failure persists
`ExecutionCompleted(status="failed")` and thereby closes the ambiguity window.
That distinction is load-bearing and is tested: a failed execution is *known*
to have finished, whereas a crashed one is not.

**`unknown` is neither `failed` nor `succeeded`, and §14 makes that mandatory.**
The disposition stays `execution_unknown`; nothing rewrites it. In particular
the operator's terminal action does not rewrite it either — see §7 below. What
`terminalize` ends is the **run**; what stays unknown is the **execution**, and
the journal keeps the `ExecutionAuthorized` record with no completion beside
the terminal record, exactly as it was written.

## 7. Operator semantics

When `resume` is withheld, `_available_actions` still returns:

* `abort` — ends the run with status `aborted`, code `OPERATOR_ABORT`;
* `terminalize` — ends the run with status `failed`, code `OPERATOR_TERMINALIZED`;
* `acknowledge` — records that a human looked, grants nothing;
* `reject_recovery` — declines this plan without ending the run.

So the run has a terminal control-plane path and M9 does not create an
operational dead end. Both terminating actions are pure state transitions:
`Controller.recover` writes a `RunTerminal` record and returns, without
resolving the argument schema, without reaching `ToolSpec.executor`, without a
model turn, and without synthesising a `ToolExecutionError` or a completion
record. Milestone 6 established that abort is not a tool failure; M9 inherits
it and proves it again against a capability where the distinction has teeth.

The vocabulary question §13 raises — whether a new term like *abandon* or
*mark unresolved* is needed — resolves to **no**. `terminalize` already means
"close a run the controller cannot complete", which is precisely this
situation, and `abort` already means "stop, without claiming the effect did not
occur". Adding a synonym would create a second terminal path to keep in step
with the first, and §13 explicitly warns against inventing a generic operator
framework for M9.

An operator still cannot say "I know it did not happen, resume it". That
remains deliberate and is Milestone 6's accepted cost: allowing it would let a
human assert a fact the controller cannot verify, which is the one thing the
operator boundary exists to prevent. The available remedy is a new run.

## 8. Failure ordering

Unchanged from Milestone 8 and re-verified for this capability:

```
VALIDATE → AUTHORIZE → POLICY → BUDGET
        → persist ExecutionAuthorized (fsync)
        → derive execution identity
        → executor
```

No mutation occurs before every precondition is durable. Within the executor
the ordering is: ceiling check on encoded bytes, then containment resolution,
then file-type checks, then `os.open`, then the spy records, then `os.write`,
then `os.fsync`. The `writes` spy is appended **before** the bytes go out, so a
test asking "could anything have happened" gets "yes" even for a write that
then failed — the same discipline Milestone 8 established, and it matters more
here because for this capability a partial effect cannot be undone by repeating.

## 9. Deliberate non-changes

**`timeout_seconds` remains declared and unenforced.** Milestone 8 recorded
this as architectural debt: the field is admitted, range-checked and journaled,
but nothing enforces it against a clock, because a wall-clock interrupt is the
non-determinism the determinism suite forbids. §19 requires that M9 not
silently make it appear enforced and not add a second field that merely sounds
like a timeout. It does neither: the debt is carried forward unchanged and
restated in §11 as `DEFERRED`.

**No new authorization mechanism, no `include_mutation=True` flag.** The
existing read-only / writable builder separation is preserved and extended by
the same pattern: a third pair of builders that a caller must name explicitly.

**No capability-specific branch in the controller.** Everything M9 needs is
already generic: the retry gate reads `re_executable` off whatever `ToolSpec`
was invoked, and recovery reads it off whatever spec the registry resolves.
Grepping the controller for the capability's name should return nothing.

## 10. What is deliberately not claimed

Not atomic. Not transactional. Not exactly-once. Not rollback-safe. Not
linearizable. Not crash-safe in the strong sense.

The guarantee this milestone actually offers is narrower and is the one §20
names: **automatic repetition is forbidden when repetition is unsafe.** That is
a property of the controller's gates, and it is provable by counting physical
executions.

## 11. Proven / Assumed / Unproven / Deferred

*Populated with measured results as the milestone proceeds; the placeholders
below are the claims the tests must establish or refute.*

**PROVEN** — by 115 executable tests in `tests/test_workspace_append.py` and by
a 17-mutation audit in which every mutation was caught by a named failing test:

* the capability occupies the fourth corner — `MUTATING`, `side_effect_free`
  False, `re_executable` False — and differs from the Milestone 8 writer in
  exactly one declared property;
* the formal criterion holds against Milestone 8's own written bound: two
  identical requests leave `seed\nentry\nentry\n` where one leaves
  `seed\nentry\n`, with the writer under the same pair of requests converging
  as the contrasting control;
* **the retry proof.** A real append followed by a *retryable* error produces
  **one** physical append and one dispatch, while the identical harness with
  the `IDEMPOTENT` writer produces **three** of each. The file's contents are
  asserted alongside the spy counts, so the claim is about the world rather
  than about a counter;
* a rejection *before* the executor leaves the ordinary repair loop intact —
  the capability gate does not turn one malformed proposal into a dead run —
  and the withheld retry reaches the audit stream as
  `retry_withheld / capability_not_re_executable` while the model-facing code
  stays `RETRY_EXHAUSTED`;
* recovery cases A-H behave as tabulated in §6, including that a *clean*
  failure lands on `execution_completed` rather than `execution_unknown`, that
  a reclassification to `IDEMPOTENT` is caught by the capability digest, that a
  tampered execution id is refused with the checksum recomputed, that a
  narrowed grant invalidates the authorization without resolving the
  disposition, and that a disappeared capability fails closed;
* planning is a read: five successive recovery plans over the same journal
  leave the append count at one and the file unchanged;
* the operator's terminal path works and cannot execute. `abort` and
  `terminalize` each end the run with no executor invocation, no model call and
  no further bytes; `resume` is refused at the *binding* layer with
  `decision_action_not_available`; a repeated terminal decision is refused with
  `run_is_terminal`; and after termination the journal still holds an
  `ExecutionAuthorized` with `side_effect_free=False` and **no** fabricated
  completion beside it;
* twelve hostile results are refused by the result schema and fifteen
  authority-named fields are refused in both the argument and result positions;
* no physical path, host detail or capability metadata reaches the model or the
  journal;
* the M9 decision surface is byte-identical across 52 repetitions, re-run five
  times.

**ASSUMED** — everything Milestones 5–8 assumed (`fsync` reaches stable
storage, appends are not reordered across it, advisory `flock` is honoured,
POSIX semantics, `O_NOFOLLOW` honoured by the filesystem, trustworthy
configured roots, no in-process code deliberately circumventing the registry),
plus one specific to this capability: that `O_APPEND` is atomic with respect to
concurrent writers, which holds on local POSIX filesystems and is known to fail
on some network filesystems.

**UNPROVEN** — atomicity of an individual append; durability across a crash
before `fsync`; behaviour on filesystems that do not honour `O_APPEND`
atomicity or `O_NOFOLLOW`; concurrent appenders outside this controller.

Also unproven, and worth naming because the code handles it without ever having
been observed: the **short-write path**. `os.write` returned the full count at
the ceiling in every measurement, so `fs_append_incomplete` is reachable in
principle and unexercised in practice. The branch exists because "not observed
here" is not "cannot happen", but no test drives it, and a test that
monkeypatched `os.write` would be proving something about the patch rather than
about the filesystem.

**DEFERRED** — enforced execution deadlines (Milestone 8's `timeout_seconds`
debt, carried forward unchanged); every filesystem operation still absent
(delete, rename, mkdir, chmod, copy); and the whole of §2's prohibition list.
