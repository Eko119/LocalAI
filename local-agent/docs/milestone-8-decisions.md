# Milestone 8 — The Constrained Artifact Writer

The first real side effect. One capability, `workspace.write`, that puts exactly
the bytes it was given at exactly one abstract location beneath one authorized
root — and nothing else.

This is a validation milestone. Its purpose is not to add filesystem power but
to prove that the controller, registry, policy, journal, recovery and operator
machinery built by Milestones 1–7 actually governs an irreversible physical act.

---

## 1. Capability purpose

Create or replace one regular file beneath one approved logical root. The
destination may or may not already exist.

Not a filesystem API. There is no append, patch, merge, delete, rename, move,
mkdir, chmod, chown, symlink, or copy — not disabled, *absent*. A mutating
request that is not "replace this one file" cannot be routed anywhere, because
there is nothing to route it to.

## 2. Input contract

```python
class WorkspaceWriteArgs(_Strict):  # frozen, extra="forbid"
    root_id: RootId  # a label from a closed set
    path: RelativePath  # the existing canonical grammar
    content: str  # bounded, UTF-8 text
```

`path` reuses `RelativePath` — the same validator the read capability uses —
with `min_length=1` because a write must name a file and the empty path denotes
the root directory. **A second path grammar was deliberately not created**: it
would be a second place for a traversal bug to live.

`content` is text, not bytes. The read capability already refuses non-UTF-8
content, so accepting arbitrary bytes here would make the pair asymmetric and
would require a base64 channel the model could misuse. The empty string is
legal — truncating a file to zero bytes is a coherent request.

The absences are the contract: no mode, no append flag, no encoding, no offset,
no permission, no owner, no "create parents", no follow-symlinks switch, no
root path. There is no parameter through which the capability could be asked to
do a second thing.

## 3. Output contract

```python
class WorkspaceWriteResult(_Strict):  # frozen, extra="forbid"
    status: Literal["success", "error"]
    root_id: RootId
    path: str
    bytes_written: int
    created: bool
```

Operational facts only. `root_id` and `path` echo the caller's own abstract
request. `created` discloses strictly less than the read capability already
does — whether a file exists inside a root the run holds a grant for — and a
caller needs it to distinguish "I made this" from "I replaced this".

No physical path, device, inode, mode, owner, or timestamp appears, and none is
collected in order to be omitted. No authorization state, grant, retry budget,
policy decision, registry object, executor object, secret, exception or
traceback can appear: `extra="forbid"` means the type has no vocabulary for
them.

## 4. Path containment — two mechanisms, two components

Containment is **reused, not reimplemented**. `PhysicalRoots` and
`_resolve_within_root` come from the read capability unchanged, so there is
exactly one containment implementation in the package.

That reuse needed one adaptation, and finding it was the first real discovery of
this milestone: **`_resolve_within_root` resolves with `strict=True`, so it
cannot resolve a destination that does not exist yet.** Measured, not assumed.
The writer therefore resolves the *parent directory* through it, which proves
the parent is inside the root by the same component-wise check, refuses a
missing parent (which is how "never create directories" is enforced — there is
no `mkdir` to forget to guard), and leaves exactly one unresolved component: a
filename that the schema guarantees contains no separator, no `..` and no NUL.

The leaf is then opened with `O_NOFOLLOW`.

**These two mechanisms guard different components, and neither is redundant.**
That was measured directly:

| Attack | Guarded by | What happens without it |
|---|---|---|
| `link_to_outside.txt` (symlinked **leaf**) | `O_NOFOLLOW` | a plain `write_text` lands outside the root |
| `linkdir/file.txt` (symlinked **parent**) | strict parent resolution | `os.open(..., O_NOFOLLOW)` **still writes outside** — the flag guards only the final component |

The second row is the one worth stating plainly, because `O_NOFOLLOW` is easy to
over-trust: it does nothing about a symlinked directory anywhere in the path.
`test_a_write_through_a_symlinked_parent_directory_is_refused` and
`test_the_two_symlink_defences_guard_different_components` pin both halves.

### Why `O_NOFOLLOW` rather than a pre-flight check

A pre-flight "is it a symlink?" check is inherently racy: an attacker who wins
the window between the check and the open redirects the write. `O_NOFOLLOW`
moves the check into the same syscall as the open, so the kernel refuses
(`ELOOP`) rather than this code hoping.
`test_a_leaf_that_becomes_a_symlink_after_the_check_still_cannot_escape` patches
`is_symlink` to lie exactly once — precisely what winning that race achieves —
and the bytes still do not land outside.

For **containment** the explicit pre-checks are then diagnosis, not defence:
the mutation audit removed the symlink check and the directory check in turn,
and each time the refusal reason changed while the outcome — no escape, no
write, the outside file intact — did not.

That holds for the two checks the flag stands behind. It does **not** hold for
the non-regular-destination check, which guards liveness rather than
containment and has nothing behind it at all; §5 records what removing it
actually does and why the earlier sweeping version of this paragraph was
wrong.

### Symlink race, stated exactly

The type check is racy and the containment property is not. If the destination
becomes a symlink after the check, `os.open` fails. If it becomes a *regular
file*, the write proceeds — into a path already proven to be inside the root.
There is no window in which bytes land outside the root.

Rejected paths — absolute, `..`, `.`, backslash, drive-qualified, UNC, NUL,
`~`, redundant separators, trailing separator, over-long, empty — are refused by
the schema at VALIDATE, before authorization and before any filesystem call.
Sixteen are parametrized twice: once through a real run asserting zero writes
and an intact outside file, once against the contract directly.

## 5. File-type policy

**Regular files only**, decided explicitly rather than inherited from whatever
the OS happens to do.

| Destination | Behaviour |
|---|---|
| does not exist | **created** (mode `0o600`) |
| existing regular file | **replaced**, mode unchanged |
| directory | refused (`fs_write_target_is_a_directory`) |
| symlink (any target) | refused (`fs_write_target_is_symlink`) |
| broken symlink | refused — a dangling link is still a link |
| FIFO / socket / device | refused (`fs_unsupported_object`) |
| parent missing | refused (`fs_not_found`) — never created |
| parent not a directory | refused (`fs_parent_not_a_directory`) |

The type is established **before** the open. That ordering was originally
written as tidiness with a footnote about FIFOs; the mutation audit turned it
into a measured requirement, and the correction is worth recording because the
first version of this section got it wrong.

The audit classified all three type checks as *layered* defence — remove one,
and a second mechanism was expected to hold, so the security outcome would be
unchanged and no test should fail. That is true for two of them:

| Check removed | What still holds | Observable change |
|---|---|---|
| symlink | `O_NOFOLLOW` → `ELOOP` | refusal slug only |
| directory | `EISDIR` from the kernel | refusal slug only |
| non-regular | **nothing** | the controller hangs forever |

The third is not layered defence at all. With the check removed, a write to a
FIFO inside an authorized root blocks indefinitely: a FIFO opened for writing
without `O_NONBLOCK` waits for a reader, and `O_NOFOLLOW` has nothing to say
about the file *type* of a component it is not following. The audit itself is
the evidence — it parked for five minutes until its own subprocess timeout
fired, and `/proc/<pid>/stack` showed the process in `fifo_open` →
`wait_for_partner` with `openat` flags `0xa0241`, i.e. `O_NOFOLLOW` set and
irrelevant.

Nothing downstream rescues that. `ToolSpec.timeout_seconds` is declared,
admitted, range-checked and recorded, but no component enforces it against a
clock — deliberately, because a wall-clock interrupt is precisely the
non-determinism `test_determinism.py` exists to forbid. So a model that
proposes a path which happens to be a FIFO inside a root it legitimately holds
could stop the agent indefinitely. This check is the only thing preventing it,
and what it defends is **liveness**, not containment.

That distinction changed how it is tested. A hang is not a failure — it is the
absence of one, so an outcome assertion cannot catch a missing check; the test
would simply never finish. `test_a_non_regular_destination_is_refused_before_
any_open` therefore asserts *ordering*: it wraps `os.open` in a spy that
refuses a FIFO rather than opening it, so a removed check fails in
milliseconds with a name attached instead of stalling the suite. Its positive
control, `test_the_open_spy_records_a_real_open`, keeps the spy honest.

The general lesson, recorded because it will recur: "a second mechanism holds"
is a claim about a specific failure mode. `O_NOFOLLOW` is a containment
mechanism, and asking it to cover an availability failure was a category error
that only measurement caught.

A note on permissions: `O_CREAT`'s mode argument is ignored when the file
already exists, so this capability **never changes a permission**. It only
chooses one for a file that did not exist, and `0o600` is the conservative
choice. Both halves are asserted.

## 6. Overwrite semantics

**Whole-content replacement only.** `O_TRUNC` empties the file at open and the
full payload is written. There is no append, no patch, no merge, and no mode
selector — so there is no partial-update semantics to reason about.

## 7. Size limits — Outcome B, and why

**No existing `FilesystemLimits` field is the semantically correct owner**, so
exactly one new field was introduced:

```python
max_file_write_bytes: int = 8_192  # 8 KiB
```

**Why not reuse `max_file_read_bytes` (256 KiB).** The two bound different
resources. A read ceiling bounds transient memory and how much data reaches the
model's context; a write ceiling bounds durable disk consumption inside a
workspace and — because arguments are persisted — how much lands in a journal
record. Sharing one value would mean raising the read limit for a read-shaped
reason silently widened how much an agent can write. That is exactly the
coupling Milestone 7 removed between `side_effect_free` and retryability.

**Why 8 KiB.** Chosen from the architecture, not for convenience. It is an order
of magnitude below the read ceiling because the resources differ, and below
`records.MAX_ARGUMENTS_BYTES` (16 KiB) so an ordinary payload is bounded by the
capability rather than by the persistence layer.

**Where it is enforced.** First, inside the executor, on **encoded UTF-8 bytes**
— before the root is resolved and before any filesystem call. Bytes, not
characters, because bytes are what land on disk and what a durable record
carries. A separate structural ceiling
(`contracts.MAX_WRITE_CONTENT_CHARS = 4 × 8_192`) bounds the string at the
schema so a hostile payload cannot force an enormous encode; four is the
maximum UTF-8 bytes per character, so it can never be the binding constraint.

**Proof that rejection precedes mutation.** Asserted at the filesystem
boundary, not in memory: the destination does not come into existence. Six
cases are tested — exactly at the limit (written), one byte over, substantially
oversized, multi-byte content under the character count and over the byte count,
**unauthorized + oversized**, and **traversal + oversized**. The last two are
the ordering tests: neither defect may let the other through.

**Shared with reads?** No — intentionally distinct, and
`test_the_write_limit_is_its_own_field_not_the_read_limit` pins that tightening
one leaves the other untouched.

**The result ceiling is unchanged.** `max_serialized_result_bytes` stays at 512
KiB and the writer enforces it on its own result.

### The journal-ceiling interaction, and a defect it exposed

Arguments are persisted, and a write's `content` is the first argument large
enough to approach `records.MAX_ARGUMENTS_BYTES`. Worst-case JSON escaping
inflates a payload six-fold (a control character becomes `\uXXXX`), so content
inside the capability's own 8 KiB ceiling can still exceed the 16 KiB record
ceiling.

Measured on the Milestone 7 tree, that raised `JournalError` from
`Controller._persist` — which is not a `_Rejection` — and **propagated out of
`run()` as an unhandled exception**. An unhandled crash is never an acceptable
outcome, so `Controller._persist_authorization` now translates it into a clean,
non-retryable `POLICY_DENIED`. The record failed to write, so nothing executed;
the refusal is opaque to the model and the true reason goes to the audit stream
as `authorization_not_persistable`. Every other durable write still propagates,
because at those points either nothing is pending or the physical call has
already happened and a loud failure is honest.

## 8. Authorization

The capability declares `requires_authorization=True` and `destructive=False`.
It decides nothing else. Whether *this run* may use it is `RunContext` plus the
two gates, unchanged.

**Two separate builders, not a flag.** `build_writable_filesystem_registry` and
`build_writable_run_context` sit beside the read-only ones rather than replacing
them. An existing deployment therefore cannot acquire the ability to mutate a
workspace by upgrading — the writer has to be asked for by name. A keyword like
`include_writer=True` would be one edit away from being set by accident, and one
keyword is not enough distance for a side effect.

The grants are independent: a run can hold a registry containing the writer and
still not be authorized to use it, and `authorize` refuses it. Tested: no
grants, a read-only grant, an unauthorized root, an unconfigured root, and
model- or executor-supplied authority fields — all refused with zero writes.

`destructive=False` is correct. It replaces one named file whose location the
run holds a grant for; it deletes nothing and reaches nothing it was not pointed
at. Admission would reject `destructive=True` here regardless, since a
destructive capability must be `MUTATING`.

## 9. Side-effect classification: `IDEMPOTENT`

Reasoned from behaviour, not from convenience.

**Not `NONE`.** Something observable happens, so an ambiguous crash is not
"nothing occurred", and the journal must not say it was.

**Not `MUTATING`.** Nothing compounds. Running the identical request N times
leaves the same file with the same bytes as running it once. Classifying it
`MUTATING` would forbid every retry and every resume — a restriction the
semantics do not earn, and it would make this capability indistinguishable from
one that genuinely accumulates.

### The bounded definition, stated exactly

> **Idempotent with respect to the destination artifact's existence and
> content.** Repeating the identical canonical request converges on the same
> file containing the same bytes, and creates no additional observable object.

What is **outside** that bound, explicitly:

* **`mtime`/`ctime` do not converge.** They advance on every write. Measured,
  and `test_filesystem_metadata_does_not_converge_and_is_outside_the_claim`
  asserts the non-convergence so the limitation stays visible rather than being
  quietly assumed away.
* **A filesystem observer** — an `inotify` watcher, a backup daemon, an audit
  log — sees N events for N runs, not one.
* **The intermediate state.** `O_TRUNC` empties the file at open, so a crash
  between truncate and write leaves a *shorter* file than either the old or the
  new content. A subsequent identical run repairs it, which is why the
  convergence claim survives; but the claim is about the end state, not about
  every instant.

The inode is stable across a rewrite (asserted), so this is the same file being
updated, not a replacement.

### Why a direct write rather than temp-file-and-replace

A temp file would make the destination's transition atomic, but it would also
create a **second observable object**. After a crash, one run leaves one stray
temp file and two runs leave two — which would have made the idempotency claim
false. A direct write has exactly one observable effect, and
`test_repeating_a_write_leaves_no_temporary_or_backup_artifacts` asserts the
absence that keeps the claim true. Simpler *and* easier to classify honestly.

## 10. What is deliberately not claimed

Not atomic. Not transactional. Not exactly-once. Not lossless.

What **is** claimed, bounded and tested: the payload is `fsync`ed before the
executor returns, so a completion record cannot claim more than the filesystem
has accepted. That does not fsync the containing directory, so a crash
immediately after *creating* a new file could still lose the directory entry —
the same bounded claim `persistence/journal.py` already makes, restated rather
than quietly widened.

## 11. Terminology, corrected

Milestone 7's documentation was internally consistent but its *implementation*
was not, and Milestone 8 found the gap. The four families are distinct:

| Family | Values | Answers |
|---|---|---|
| side-effect classification | `NONE`, `IDEMPOTENT`, `MUTATING` | what the capability does to the world |
| repeatability | `re_executable` | may the controller run it again? |
| evidence | execution-known / execution-unknown | what does the journal establish? |
| delivery | at-most-once / at-least-once | how many times can it run? |

They are **independent axes**. Specifically:

* `IDEMPOTENT` is **not** inherently at-most-once. This writer is at-least-once
  under retry — three attempts produce three physical writes — and that is safe
  precisely because repeating converges.
* `NONE` is **not** inherently at-least-once. It is at-least-once *here* because
  repeating is free, not because `NONE` implies it.
* An `IDEMPOTENT` execution after an ambiguous crash is **execution-unknown**
  (evidence) **and** re-executable (safety). Those are different questions.

### The implementation gap this exposed

Milestone 7 fixed the *in-run retry* gate to consult `re_executable`, but
`recovery._available_actions` still keyed `resume` on the disposition — which is
derived from `side_effect_free`. The two disagreed: an `IDEMPOTENT` capability
was retried inside a run and refused a resume after a crash, for the same
operation.

Milestone 6's rule said "`execution_unknown` does not offer resume" because "the
tool is not side-effect free … so re-running might duplicate a real side
effect". That premise was true when not-side-effect-free implied
not-repeatable. With three values it splits. The **invariant** Milestone 6 was
protecting is *never re-run something whose repetition might duplicate an
effect* — which `re_executable` states exactly.

So `resume` is now the conjunction of three independent facts: the execution is
outstanding, the gates still pass, and the capability is re-executable. A
`MUTATING` execution is still never resumable, which is the case the rule was
written for. The disposition is unchanged and stays honest: an ambiguous crash
on an `IDEMPOTENT` capability is still `execution_unknown`, because the evidence
genuinely is unknown. The operator is shown both facts —
`side_effect_free` (did anything happen) and `re_executable` (is repeating
safe). `test_only_a_pending_re_executable_authorized_execution_is_offered_a_resume`
walks the whole 5 × 2 × 2 space.

## 12. Retry semantics

The controller's branch, unchanged in shape:

```
error.retryable ∧ (nothing ran ∨ invoked.re_executable) ∧ attempt < max_attempts
```

Measured against a real executor that performs a genuine write and then raises a
retryable error:

| Classification | Physical writes for a budget of 3 |
|---|---|
| `IDEMPOTENT` (this writer) | **3** — permitted, because repeating converges |
| `MUTATING` (same executor, one field changed) | **1** — withheld, with a `retry_withheld` audit event |

The contrast is the point: the same executor, the same error, the same budget,
and only the declared classification differs. A pre-execution failure still
retries for any classification, because nothing ran. A non-retryable denial
stops after one attempt.

**Repeatability is not success.** Three writes and a failed run is exactly what
the counters show; nothing infers a completed execution from the fact that
repeating was allowed.

## 13. Execution identity

Unchanged and re-proven for the writer. Identity is
`sha256(run_id, step_id, attempt, tool, canonical arguments)`. Same inputs give
the same identity; a different path, different content, different attempt or
different run all give different ones. The recorded identity re-derives from the
run's own state — the writer invents nothing and has no identity of its own.

## 14. Journal interaction

The existing journal, unchanged. No second persistence mechanism, no second
checksum, no parallel ledger. The writer never constructs a durable record —
asserted against its AST — so it cannot manufacture the evidence of its own
execution.

**One consequence must be stated rather than glossed over: a write's content is
persisted.** Milestone 5 persists an execution's canonical arguments, because
execution identity is derived from them and recovery re-validates them against
the live schema. Content *is* an argument. So the bytes a run writes are durable
in the journal for as long as the journal exists.

This is required by the existing contract, not incidental: excluding content
would mean the execution identity did not cover it and recovery could not
re-validate it, breaking Milestone 5, 6 and 7 invariants at once.
`test_written_content_is_persisted_as_an_argument_and_that_is_stated` asserts
it so the fact is visible rather than surprising. The *result* is still not
persisted — a completion carries a status and a slug, never the payload.

**Operational consequence:** a journal is as sensitive as the most sensitive
thing ever written through this capability. That is a deployment fact worth
knowing, and it is why this section exists rather than a footnote.

## 15. Crash and ambiguous execution

| Case | Injection | Result |
|---|---|---|
| A | crash before the authorization is durable | no write; `no_execution_authorized` |
| B | authorization durable, nothing executed | no write; `execution_unknown`, resume offered |
| C | crash during execution | write landed; `execution_unknown`, `execution_status is None` |
| D | write landed, completion evidence lost | **the bytes are on disk and the system still does not claim success** |
| E | completion durable | `execution_completed`, status `succeeded` |

Case D is the one the milestone singles out, and it behaves correctly: recovery
reasons from durable evidence, not from what the filesystem currently appears to
contain. A different run could have written those bytes. Nothing infers success
from observation.

## 16. Operator recovery

The existing control plane, with no writer-specific API. Inspection exposes the
capability, its `side_effect_free`, its `re_executable`, and
`capability_verified`. The capability digest is checked, the live registry
definition is re-resolved, the current argument schema re-validates, the gates
re-run, and the execution identity re-derives — all before any executor.

Tested for the writer specifically: a changed capability definition is refused
(`journal_capability_digest_mismatch`), a narrowed grant withdraws the resume
option, a disappeared capability is refused
(`journal_tool_not_in_registry`).

**Is repeating after an ambiguous execution safe?** For this capability, yes,
under the §9 bound — and that is documented rather than assumed. Resuming after
`execution_unknown` re-runs the identical request, which converges on the same
content. It does **not** mean the first attempt is known to have succeeded, and
nothing in the system says it does.

## 17. Executor isolation

Asserted behaviourally and against the module's AST. The writer imports no
control-plane module, constructs no `RunContext`, `ToolRegistry`, `Controller`,
`RunJournal` or durable record, calls no model, invokes no other capability,
reaches no gate, and assigns to no authority attribute.

It imports **only `os`** from the filesystem families — not even `pathlib`. It
receives already-resolved `Path` objects from the shared helper and never
constructs one, so it holds strictly less filesystem surface than the reader.

`workspace_fs.py` remains provably read-only: the writer is a separate module
precisely so Milestone 2's assertions did not have to be weakened, and
`test_the_read_only_executor_did_not_acquire_a_write_primitive` guards that.

## 18. Model boundary

Twenty authority-shaped field names are refused in both positions — at the
envelope (`TOOL_CALL_MALFORMED`) and inside `arguments` (`SCHEMA_INVALID`) —
with zero writes. The model cannot name a physical root: `root_id` is a label
from a closed set, and a physical path supplied as one is refused.

The model-visible surface carries the capability's name and argument schema and
nothing else — no `side_effect`, `re_executable`, `requires_authorization`,
`destructive`, `timeout_seconds`, `capability_digest`, executor identity, or
physical root. It *does* learn `workspace.write` exists, which it must in order
to propose it.

## 19. Result boundary

Twelve hostile results — carrying `authorized`, `authorized_tools`,
`max_attempts`, `policy`, `registry`, `executor`, a wrong status, wrong types, a
missing field, a non-mapping, `None`, an unknown root — all fail verification
and none alters grants, policy, budget, registry, state, identity or operator
authority. Injection-shaped *content* is written as bytes and changes nothing.

## 20. Secret and data flow

Runtime sentinels through the real data flow. A physical root never reaches a
result, an event, a model payload, a journal record or a capability digest. An
API key never reaches a write argument, the written file, a result, a journal
record, an event, or the config's `repr`. Capability digests contain no content.
A positive control proves the probe can detect a leak.

## 21. Proven

By executable tests in this commit: an authorized write creates and replaces
files and returns the documented result; sixteen hostile paths are refused with
zero writes and an intact outside file; a symlinked leaf, a symlinked parent, a
symlink to another root, a broken symlink, a directory, a FIFO and a missing
parent are each refused with zero writes; a non-regular destination is refused
without `os.open` ever being handed it, with a positive control proving the
spy would notice if it were; a leaf that becomes a symlink after the check
still cannot escape; content exactly at the limit is written and one
byte over is not; oversized content creates no file; unauthorized-and-oversized
and traversing-and-oversized both perform zero writes; the write limit is its
own field, tightening it is honoured, and it stays below the journal's argument
ceiling; an unpersistable payload is refused
rather than crashing; no grant, a read-only grant, an unauthorized root and an
unconfigured root all refuse with zero writes; the read-only registry and run
context contain no writer; the capability is admitted and classified
`IDEMPOTENT` with both derived properties; five identical writes converge with
no accumulation and no stray artifacts; metadata does not converge; three
physical writes for `IDEMPOTENT` under retry versus one for `MUTATING`;
execution identity varies with path, content, attempt and run; crash cases A–E
behave as tabulated; a changed capability definition, a narrowed grant and a
disappeared capability each block recovery; twelve hostile results stay data;
twenty authority fields are refused in both positions; the model-visible surface
leaks no capability metadata; sentinels do not reach the surfaces that must not
carry them; the decision surface is byte-identical over 100 repetitions.

By mutation: fifteen required mutations each caught by a named failing test,
and two defence-in-depth mutations where a second mechanism held and the
security outcome was unchanged — with the source restored byte-for-byte after
every one and the full suite re-run green.

Those counts started as fourteen and three, and the audit's own defects are
part of what it proved. Two mutations first reported as MISSED were not gaps at
all: the `-k` expressions containing spaces had been split into extra path
arguments, so pytest selected nothing or the wrong subset. That is testing rule
18 in both directions — the M7 audit hit it as a false *catch*, this one as a
false *miss*, and the fix in both cases was to read the output rather than the
exit code. Selectors are now passed as argument lists, and a subprocess timeout
counts as an audit failure rather than a detection.

The third reclassification was substantive rather than clerical, and is the
finding recorded in §5: the non-regular-destination check moved from LAYERED to
REQUIRED once measurement showed that removing it hangs the controller instead
of degrading its error message.

The pattern across all three is the same. An audit is production code for the
purpose of trusting its output, and an unexamined green result from it is worth
no more than an unexamined green test.

## 22. Assumed

Everything Milestones 5–7 assumed (`fsync` reaches stable storage, appends are
not reordered across it, advisory `flock` is honoured, POSIX, that whoever can
call the operator API is the operator, and that no in-process code deliberately
circumvents the registry's guards), plus two specific to this capability:

* that `O_NOFOLLOW` is honoured by the underlying filesystem — it is POSIX and
  Linux-verified here, but a network or FUSE filesystem could differ;
* that the physical roots configured by wiring are themselves trustworthy. A
  root whose *own* path is attacker-controlled is outside this model.

## 23. Unproven

Atomicity of the write. Durability of a newly created file's directory entry
across a crash. Exactly-once execution. Idempotency with respect to filesystem
metadata or to an external observer — explicitly outside the stated bound.
Behaviour on filesystems that do not honour `O_NOFOLLOW`. Concurrent writers to
the same destination from outside this controller: the journal lock bounds this
controller's own concurrency and says nothing about other processes.

Bounded execution time. `ToolSpec.timeout_seconds` is declared, admitted,
range-checked and recorded, and nothing enforces it — see §5. The writer avoids
the one blocking case it can reach by refusing non-regular destinations before
the open, which is a fix for this capability rather than a general guarantee. A
capability that could block for another reason would have nothing to stop it,
and giving the controller a real execution deadline is deferred work, not a
property this milestone provides.

Live LocalAI inference remains unobserved; nothing in this milestone changed or
needed that.

## 24. Deferred

Every other filesystem operation — delete, rename, mkdir, chmod, copy, append.
A `MUTATING` capability, which would be the first to exercise the
non-re-executable path against a real effect. Byte (non-UTF-8) content.
Directory-entry durability. Everything in §2's exclusion list: shell,
subprocess, MCP, browser, plugins, workers, queues, distributed execution,
network mutation, autonomous recovery, and authenticated operator identity.
