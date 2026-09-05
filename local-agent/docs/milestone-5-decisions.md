# Milestone 5 — Durable Run State, Crash Recovery, and Execution Semantics

This milestone makes a crashed run recoverable without asking the model what
happened. It records what was decided, why, and — in the last section — a
careful separation of what the tests establish from what they cannot.

## 1. Architecture: an append-only journal, no snapshots

**Chosen:** one append-only JSONL journal per run, each line an integrity-
checked envelope around one typed, versioned record. No snapshots, no
database.

Three pieces of repository evidence drove that, rather than a preference for
event sourcing:

* **Runs are bounded.** `RunContext.max_attempts` defaults to 3 and each
  attempt emits at most a handful of durable records. A snapshot layer
  optimizes a replay cost that does not exist here, and introduces a second
  representation that can disagree with the first — precisely the "second
  authority" this milestone forbids.
* **The adversarial tests need a transparent format.** §20 requires mutating
  specific persisted fields — swapping a tool name, altering arguments,
  forging a completion. Against SQLite those tests would largely exercise
  SQLite. Against one line of JSON they exercise *this* validation.
* **Zero dependencies.** `json` was already permitted; `hashlib`, `uuid`,
  `os`, `fcntl`, and `pathlib` are standard library. `sqlite3` is equally
  dependency-free and would have been the right answer at a scale this
  project does not have.

Records: `run_started`, `execution_authorized`, `execution_completed`,
`run_terminal`. That is the complete set, and each exists because recovery
cannot be decided without it.

## 2. Authority: the journal is evidence, never authority

The controller and its state machine remain authoritative. A record is a
durable *representation* of a decision the controller already made, and on the
way back in it is re-checked against things the controller can compute for
itself:

| Claim in the journal | How it is re-checked |
|---|---|
| the run's identity | must match the live `RunContext.run_id`, on every record |
| the retry budget | must equal the live `RunContext.max_attempts` |
| the tool | must exist in the live `ToolRegistry` |
| the arguments | must re-validate against that tool's current schema |
| the execution identity | re-derived from run, step, attempt, tool, arguments |
| "safe to repeat" | must match the live `ToolSpec.side_effect_free` |
| a completion | must refer to an authorization that exists |
| anything after a terminal | refused outright |

Anything that fails raises `RecoveryError`. There is no repair path, and
`plan_recovery` never mutates a record. This is what §3 asks for: when the
persisted state disagrees with executable invariants, recovery fails closed.

**Why this matters more than the checksum.** The checksum catches accidental
corruption and truncation. It cannot catch a deliberate edit — there is no key
to authenticate with, and the journal sits in the same trust domain as the
process that writes it. Inventing an HMAC whose key lives beside the data it
protects would be theatre. So the adversarial tests recompute the checksum
after every mutation, and what rejects them is re-derivation.

## 3. Run identity

`new_run_id()` returns a `uuid4` hex string: random, not a timestamp (two runs
in the same millisecond must not collide) and not a counter (which would need
durable state of its own to survive a restart). It is bounded and restricted
to `[A-Za-z0-9._-]`, because a run's journal is named after it and a value
containing `/` or `..` would otherwise choose where the journal is written.
That constraint is enforced by the record schema and tested.

The model never supplies, influences, or sees a run id.

Production identity generation is deliberately *not* deterministic. Tests
inject explicit run ids instead, so the determinism suite never depends on
weakening real identity generation (§28).

## 4. Execution identity

```
execution_id = sha256(run_id | step_id | attempt | tool | canonical_arguments)[:32]
```

Derived rather than random, and that is the point: recovery can recompute it
from the run's own state and compare. A journal whose `execution_id` does not
match the tool and arguments recorded beside it has been altered, and is
rejected without needing a secret. Every input participates, which is tested
by changing each one in turn.

It is derived from controller-owned values only. The model contributed the
*proposal*, but by the time this is computed the proposal has been
schema-validated, authorized, and policy-checked, and the arguments are the
canonical typed form rather than the model's raw text.

One consequence worth stating: identity is over *semantic* arguments. A record
that omits a schema-defaulted field normalizes back to the same canonical form
and the same identity. That is not a gap — the effective execution is
identical, so there is nothing to gain — and it is covered by a test that says
so explicitly.

## 5. The durability boundary, stated precisely

A record is durable when its line has been written, `flush()`ed out of
Python's buffer, and `fsync()`ed to the storage device. `RunJournal.append`
returns only after that, which is what lets the controller treat "append
returned" as "this survives a crash".

What is **not** claimed:

* The containing directory is not fsynced. On some filesystems a crash
  immediately after the journal file is first created could lose the file
  entry itself.
* A crash *during* a write may leave a partial final line. That line is
  dropped on read, not repaired: the record it would have become was never
  durable, so the correct interpretation is that it does not exist. A partial
  line anywhere other than the end is corruption and is refused.
* No claim is made about the storage device honouring `fsync`.

## 6. Crash windows

| Window | Situation | Behaviour |
|---|---|---|
| **A** | crash before the authorization is persisted | `no_execution_authorized`. Recovery will not execute. No physical execution can have happened, because the write-ahead record precedes the executor call. |
| **B** | authorization persisted, crash before execution | `execution_pending_repeatable` for a side-effect-free tool; the pending execution and its identity are identified deterministically. |
| **C** | crash *during* execution | The genuinely ambiguous case. Resolved by `ToolSpec.side_effect_free`: repeatable tools may be re-executed, everything else becomes `execution_unknown`. See §7. |
| **D** | execution finished, crash before the completion is persisted | Indistinguishable from C from the journal's point of view, and deliberately treated identically. |
| **E** | completion persisted, crash before verification | `execution_completed`. The ambiguity is closed; recovery knows the physical call finished and will not repeat it. |
| **F** | terminal persisted, crash before exit | `terminal`. A finished run stays finished; recovery will not restart execution. |

Each window has a test that drives a real controller into it with an injected
crash at a structural boundary — no sleeps, no timing — and then asserts the
recovery disposition *and* the spy executor's physical call count.

## 7. Execution semantics — stated without hedging

**The system does not provide exactly-once execution in general, and does not
claim to.** Controller-level duplicate suppression cannot make an arbitrary
external side effect exactly-once; that requires cooperation from the executor
itself. What the system provides, per tool:

**For tools declared `side_effect_free=True`** — every tool that exists today:
`workspace.read`, `workspace.list`, and `file_search`, all of which only read.
Execution is **at-least-once**, and because repetition produces no additional
effect, it is *observationally* equivalent to exactly-once. That equivalence is
a property of the tools, not of the controller, and it evaporates the moment a
tool acquires a side effect.

**For tools declared `side_effect_free=False`** — the fail-closed default, and
the state of any future write tool until someone deliberately says otherwise.
Execution is **at-most-once up to the ambiguous window**: crash windows A, B,
E, and F are unambiguous, and windows C and D produce an explicit
`execution_unknown` disposition with `requires_operator = True`. Recovery
stops. The system does not guess whether the effect happened.

`ToolSpec.side_effect_free` is the single field added for this, justified by
exactly that decision. It defaults to `False`, it is on a frozen dataclass
built by trusted wiring, and the model cannot reach it. A journal claiming a
tool is safe to repeat when the live `ToolSpec` says otherwise is refused.

## 8. Recovery works with LocalAI switched off

`plan_recovery` and `replay` are pure functions of the journal, the live
registry, and the frozen `RunContext`. `recovery.py` imports no model adapter,
no transport, no network module, no filesystem module, and reads no
environment variable — asserted structurally, not just by convention.

Recovery never asks the model what happened, never reinterprets old model
output, never discovers tools, never bypasses policy, and never increases a
budget. It consumes records as data.

## 9. Replay is observational

`replay` takes `records`, `registry`, and `run_context` — and no executor. It
never reads `ToolSpec.executor`, which is asserted against its own AST with
docstrings stripped. It re-validates through `plan_recovery` first, so
replaying an untrusted journal is not a way around the checks recovery
applies, and a journal that fails validation raises before anything is
reconstructed.

A corrupted or malicious journal therefore has nothing in replay to trigger.
A test drives a mutated journal through `replay` and asserts the spy executor's
call count is zero.

## 10. Concurrency boundary

Two live recoveries of the same run must not both proceed. The journal holds an
advisory `flock` for its lifetime, and a second holder is **refused
immediately** rather than queued — `JournalLockError`, distinct from
corruption.

`flock` specifically, rather than an `O_EXCL` lock file: the kernel releases a
`flock` when the holding process dies, so a crashed run's journal is
immediately recoverable. An exclusive lock file would have had the opposite and
wrong behaviour — a crash would leave a stale lock that blocks recovery
forever.

This is a single-host, single-process-per-run boundary. It is not distributed
coordination, and nothing here attempts to be.

## 11. Resource limits

| Limit | Value | Behaviour when exceeded |
|---|---|---|
| events per run | 1,000 | append refused; read refused |
| serialized record | 64 KiB | refused |
| tool arguments | 16 KiB | refused |

All are rejections. Authoritative data is never silently truncated — the same
rule Milestone 2 applied to file reads and directory listings.

## 12. What is persisted, and what is deliberately not

Persisted: run id, budget, attempt, step, tool name, canonical arguments,
execution identity, the side-effect flag, execution status and a controller-
private reason slug, terminal status and code, sequence numbers, and a schema
version.

Not persisted: API keys, `Authorization` headers, environment variables, model
reasoning, narrative, raw prompts, raw model responses, physical filesystem
roots, host paths, exception tracebacks, or tool output payloads. Completion
records the *outcome*, not the result: tool output can be large, can contain
file contents, and is not needed to reconstruct controller state.

The end-to-end filesystem recovery test asserts that neither the journal nor
the recovery plan contains the fixture's physical path.

## 13. Security assumptions

The realistic threat model is a local file in the same trust domain as the
process: it can be corrupted by a crash, and it can be edited by anything
running as this user. It is **not** assumed to be tamper-proof.

What that buys, and does not:

* Corruption and truncation are detected (checksum, sequence continuity).
* Semantic tampering is defeated by re-derivation and re-validation, not by
  the checksum — a journal cannot change a tool, its arguments, the budget,
  the safety flag, or resurrect a terminated run.
* An attacker with write access to the journal *and* the ability to construct
  a fully self-consistent history could describe a different legal run. What
  they cannot do is describe an *illegal* one: every avenue that would matter
  — a larger budget, an unknown tool, invalid arguments, an unauthorized
  completion — is checked against live authority.
* Persisted content never becomes an instruction. A record carrying model
  prose in an argument is still just an argument, and a test asserts it.

## 14. Proven, assumed, not guaranteed, deferred

### Proven — established by tests in this repository

Crash windows A–F produce the stated dispositions, with physical execution
counts measured by spy executors. The corruption matrix (malformed JSON, torn
lines, invalid UTF-8, missing fields, unknown fields, unknown record types,
unsupported schema versions, negative and impossible budgets, duplicate
sequences, sequence gaps, checksum mismatch) fails closed in every case.
Adversarial mutations with recomputed checksums — swapped tool, altered
arguments, altered root, replaced execution identity, forged completion,
forged safety flag, out-of-range attempt, record after terminal — are all
refused. Replay performs zero physical executions, including on a mutated
journal. A second live journal holder is refused. Recovery imports nothing
network- or model-related. Six recovery scenarios replay identically over 100
repetitions each, with byte-stable serialization. The full end-to-end path
runs against the real read-only executor with a simulated crash.

### Assumed — depends on layers below this code

That `fsync` reaches stable storage; that the filesystem does not reorder
appends across an fsync; that `flock` is honoured (it is advisory, and a
process that never asks for the lock is not stopped by it); that POSIX
semantics apply — `fcntl` is not available on Windows.

### Not guaranteed — deliberately not claimed

Exactly-once execution in general. Recovery from a torn write *within* a
record that still parses and checksums correctly — that would require the
attacker to be doing the corrupting, which is §13's territory. Durability
across a crash between file creation and the first fsync of the directory
entry. Any protection against an attacker who can rewrite the journal into a
fully self-consistent alternative history. Multi-host or multi-process
coordination beyond one advisory lock.

### Deferred — outside this milestone by §2

Conversational memory, RAG, vector stores, Qdrant, semantic retrieval, MCP,
browser automation, shell or subprocess execution, workers, concurrency,
orchestration, model routing, fallback models, streaming, model downloading,
GPU management, dynamic tool discovery, registry mutation, and OS sandboxing.
Also deferred: automatic resumption — `plan_recovery` returns a *plan*, and
acting on it is a separate decision this milestone does not automate.
