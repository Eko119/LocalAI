# Milestone 7 — Capability Contract and Tool Authoring Boundary

Milestones 1–6 built the machinery around capabilities. This one asks what a
capability has to *be* before that machinery will touch it:

> **What must be true before a capability is admissible to the controller, and
> what prevents the capability from becoming an authority itself?**

Nothing here adds power. Four defects were found by measuring the tree at
`83e95d0` rather than by reading it, and each fix is the smallest thing that
closes the one that was measured.

---

## 1. What inspection found

Every claim below was produced by running code against the pre-Milestone-7
tree, not by reasoning about it.

**`ToolRegistry` performed no admission at all.** The only check was duplicate
names. It accepted an empty capability name, `"../../etc/passwd"` as a name, a
timeout of `-5`, an `args_schema` of `dict` (not a `BaseModel` subclass), an
executor object with no `execute` method, and — the one that matters — a
capability declaring `destructive=True` with `requires_authorization=False`.

That last combination is an authority hole, not an aesthetic one.
`policy.authorize` consults a run's tool grants *only* when the capability
declares `requires_authorization`, so such a capability runs for a run holding
no grants whatsoever. Measured directly against the gate:
`authorize(destructive_spec, args, RunContext(authorized_tools=frozenset()))`
returned `allowed=True`.

**The registry was mutable after construction.** `_by_name` was a plain dict on
a plain object: `registry._by_name["evil"] = spec` inserted a capability into a
live registry, and `registry._by_name = {}` replaced the whole map. The
module's own docstring claimed "no mutation API of any kind", which was true of
the public surface and not of the object.

**In-run retry ignored the side-effect classification entirely.** Retry
consulted only `contracts.RETRYABLE_CODES`. A capability that performed an
irreversible act and then raised `ToolExecutionError` was re-run once per
attempt in the budget — three physical side effects for `max_attempts=3` —
whether or not it was declared `side_effect_free`. Milestone 5 had reasoned
only about crash recovery; the live path had never been gated.

**A capability definition could change under an authorized execution
undetected.** `args_schema` and `result_schema` are classes, and Python classes
are mutable: `model_fields`, `model_config` and even `__pydantic_validator__`
can be replaced, and `model_rebuild(force=True)` makes the change take effect.
A schema *widened* to `extra="allow"` after an execution was authorized left
the recorded arguments valid and the execution identity intact, so every
Milestone 5 and 6 check passed and recovery offered a resume for a capability
that now meant something different.

## 2. The capability contract

### Identity

**The existing tool name is sufficient as the capability's identity, and it was
not sufficient as a name.** No versioning was introduced — nothing in the
repository needs two concurrent versions of a capability, and adding a version
field because it sounds architecturally proper would be a speculative
abstraction with a real cost: another field for `dataclasses.replace` to carry
and another thing to get out of step.

What was missing was *validation* of the name. It is an audit key, a
model-visible label, and a journal value, so it is now bounded at 64 characters
and restricted to a dotted lower-snake namespace. `workspace.read` is legal;
`../../etc/passwd`, `workspace/read`, `FileSearch`, `file search`, `1tool`, and
a name containing a NUL byte are not.

Separately, a capability now has a **content address** — see §4.

### Arguments

Unchanged, and re-stated because the contract needs saying somewhere:
`args_schema` is a frozen Pydantic model with `extra="forbid"`; validation is
deterministic and happens in the controller's VALIDATE state; the canonical
representation is `args.model_dump(mode="json")`, which is what execution
identity is derived from; the maximum serialized size is
`MAX_ARGUMENTS_BYTES` (16 KiB) at the persistence boundary; a violation is a
`SCHEMA_INVALID` rejection with sanitized field errors and no coercion. What
Milestone 7 adds is that `args_schema` **must be a `BaseModel` subclass** —
previously `dict` was accepted and would have failed later, deeper, and less
clearly.

### Results

Also unchanged and re-stated: `result_schema` is validated in VERIFY before
anything reads the result; a malformed result is `VERIFICATION_FAILED`, never a
crash; size is bounded by `FilesystemLimits.max_serialized_result_bytes` for
the filesystem capability; and a result is **data, never instruction** —
nothing re-reads it as control input. Milestone 7 adds the same `BaseModel`
requirement and a ten-case hostile-result matrix, including results carrying
`authorized`, `max_attempts`, `authorized_tools` and a nested `policy` object.
All fail verification; none changes the run's authority.

### Authorization

| Who | Declares / decides |
|---|---|
| the capability | `requires_authorization`, `destructive` — *what kind of thing it is* |
| `RunContext` | `authorized_tools`, `authorized_roots`, `max_attempts`, ceilings — *what this run may do* |
| `policy.authorize` | whether the run holds the grants this call needs |
| `policy.evaluate_policy` | whether the operational rules permit this concrete request |
| the model | nothing — it proposes a name and arguments, both untrusted data |

A capability declares what it *is* and never what it is *allowed*. That
separation is why a capability cannot widen its own authority — and the one
place it leaked, `destructive` without `requires_authorization`, is now
inadmissible.

## 3. Side effects, retry, idempotency — three questions, not one

`side_effect_free: bool` was answering two different questions with one answer:

* *did anything observable happen?* — which decides what an ambiguous crash
  means and what an operator is being told;
* *is running it again safe?* — which decides whether the controller may retry.

Collapsing them was survivable only because every capability shipping today is
`NONE`, where both answers coincide. So `SideEffect` is now three-valued, and
the two questions get separate derived properties:

| `side_effect` | `side_effect_free` | `re_executable` | Meaning |
|---|---|---|---|
| `NONE` | True | True | No observable effect. Reading a file. |
| `IDEMPOTENT` | False | True | Has an effect; N runs equal one run. |
| `MUTATING` | False | False | Effect compounds. Sending, appending, charging. |

Both properties are **derived, not stored**, so they cannot drift from the
classification, and both raise on assignment. The default is `MUTATING` — a
capability nobody has classified is assumed to compound.

**Retry is emphatically not `side_effect_free`.** The controller's retry
condition is now a conjunction of three controller-owned facts:

```
error.retryable                     # contracts.RETRYABLE_CODES
AND (invoked is None or invoked.re_executable)   # the capability contract
AND attempt < run_context.max_attempts           # the frozen RunContext
```

`invoked is None` means the attempt was rejected before the executor was
reached, so nothing happened and the ordinary repair loop is untouched — a
malformed proposal still gets its three chances for any classification.

The model-facing code stays `RETRY_EXHAUSTED` when the gate withholds a retry.
From the model's side no further attempt is available, which is what that code
means, and saying *why* would leak the capability's classification onto a
channel that must not carry it. The true reason goes to the audit stream as a
`retry_withheld` event with `reason="capability_not_re_executable"`.

### Ambiguity, stated without hedging

Milestone 5's semantics are unchanged and are **not** strengthened here:

* the system does not provide exactly-once execution, in general or under
  recovery, and does not use the phrase where it cannot enforce it;
* `NONE` is at-least-once and observationally equivalent to exactly-once
  *because of the capability*, not because of the controller;
* everything else is at-most-once, with an explicit `execution_unknown`.

Note the asymmetry the three-way split makes visible: an `IDEMPOTENT`
capability is safe to **retry** after a *known* failure and is still
`execution_unknown` after an *ambiguous* crash. "Did it happen" and "is
repeating safe" are different questions, and the journal only answers one.

## 4. Capability identity, and what immutability cannot reach

`ToolSpec` is frozen and every field refuses assignment, including new ones.
But a spec *references* two classes, and Python cannot freeze a class. That
limitation is asserted by a test rather than glossed over:
`test_the_schema_classes_a_spec_points_at_remain_mutable` widens a schema, uses
it, and restores it.

The contract's answer is to make the change **detectable** rather than claim it
is impossible:

```
capability_digest = sha256(canonical_json({
    schema_version, name,
    args_schema.model_json_schema(), result_schema.model_json_schema(),
    requires_authorization, destructive, side_effect, timeout_seconds,
}))[:32]
```

Same technique as execution identity and plan identity. The digest is recorded
on `ExecutionAuthorized`, and recovery compares it against the live definition:
a mismatch is a fatal `journal_capability_digest_mismatch`.

**The executor is deliberately absent from the digest.** A test that
substitutes a spy for the production executor must exercise the *same*
capability, or every recovery test would be about a different one. The cost is
stated rather than hidden: the digest does not detect an executor swap.

**And, as with the Milestone 5 checksum, this detects drift and not tampering.**
An attacker who can rewrite the journal can recompute the digest. What it
catches is the case nothing else could — a definition that changed underneath
an authorized execution while the arguments still validated and the identity
still re-derived.

A record with **no** digest predates the field. It is reported as
`capability_verified=False` rather than treated as verified, and that flag
reaches the operator's inspection view. Absence of evidence is reported as
absence.

## 5. Registry admission boundary

* **Who may construct a `ToolSpec`:** anyone, in principle — it is a plain
  dataclass. In practice, `test_only_capability_builders_construct_a_toolspec`
  pins construction to the two executor modules.
* **Who may register one:** `wiring.py`, and only there
  (`test_only_trusted_wiring_and_capability_builders_construct_a_registry`).
* **Is registration mutable?** No. There is no `register`, `replace`, `remove`
  or `update`; the map is a `MappingProxyType`; `__setattr__` refuses rebinding
  and `__delattr__` refuses deletion.
* **Is replacement permitted?** No. Duplicate names raise
  `registry_duplicate_capability_name` rather than last-one-wins, because
  silent replacement is exactly how a capability would come to mean something
  different from what an earlier run authorized.
* **Aliases:** none. One name, one capability.
* **Can a changed `ToolSpec` affect an existing run?** Not silently. Recovery
  re-resolves the tool, re-validates arguments against its *current* schema,
  re-checks `side_effect_free`, re-derives the execution identity, and now
  compares the capability digest.
* **What if a capability disappears?** `journal_tool_not_in_registry`, fatal.

**There is deliberately no "already admitted" marker.** A marker would be a
field, and `dataclasses.replace` copies fields — so a spec derived from an
admissible one could carry the mark while having changed the very properties
that were checked. `ToolRegistry` therefore runs `admit` itself,
unconditionally, on every entry.
`test_a_replaced_spec_is_re_checked_rather_than_carried_forward` is that
attack, refused.

### The honest limitation

In-process Python has no tamper barrier. `object.__setattr__` reaches past any
guard, and the schema classes stay mutable no matter what the registry does. So
this is **not** immunity. What it is: every sanctioned mutation path removed, so
careless or accidental mutation fails loudly, plus a content address so a
determined one is detectable afterwards. Saying more than that would be false.

## 6. Executor isolation

An executor's entire world is one validated arguments object. Asserted two
ways.

**Behaviourally**, `AuthorityHungryExecutor` tries, from inside `execute`, to
reach `max_attempts`, `authorized_tools`, the registry, an executor, the
controller, and to mutate its own arguments. Every one fails; the arguments are
a frozen Pydantic model.

**Structurally**, against module ASTs: an executor module imports none of
`controller`, `wiring`, `recovery`, `operator`, `journal` or `state_machine`;
constructs no `ToolRegistry`, `RunContext`, `Controller` or `RunJournal`;
constructs no durable record; calls no model; and assigns to no authority
attribute. `.executor` is reachable from exactly one production module —
`controller.py`.

One boundary was drawn more precisely than first written.
`executors/workspace_fs.py` *does* import `policy`, for `FilesystemLimits`,
`DEFAULT_FILESYSTEM_LIMITS` and `LEGAL_ROOT_IDS`. A blanket module ban would
have failed on it, and the temptation would have been to relocate code for the
test's convenience. The real distinction is that **enforcing a ceiling someone
else set is the executor's job; deciding one is not** — so the ban is on the
deciding names (`RunContext`, `authorize`, `evaluate_policy`, `Decision`),
which is narrower and truer than "no policy import", with its own poisoned
positive control.

An executor may **deny**, via `ToolDenialError`, and can never grant: there is
no code path by which an executor hands itself authority it was not wired with.

## 7. Model boundary

The model cannot change a `ToolSpec`, the registry, grants, authorization,
policy, retry semantics, side-effect or idempotency classification, executor
identity, recovery authority, journal authority, or terminality. Eighteen
authority-sounding field names — `authorize`, `grant`, `executor`, `policy`,
`retry`, `side_effect_free`, `side_effect`, `idempotent`, `operator`,
`recovery`, `terminal`, `tool_spec`, `registry`, `capability_digest`,
`admitted`, `re_executable`, `max_attempts`, `authorized_tools` — are tested in
both positions:

* at the **envelope**, `RawToolCall` forbids extras, so the proposal is
  `TOOL_CALL_MALFORMED` before any tool is resolved;
* inside **`arguments`**, the capability's own schema forbids extras, so it is
  `SCHEMA_INVALID`.

Neither reaches an executor. There is no branch anywhere that reads these
names, which is why the list can grow without the controller growing.

The model-visible surface carries a name and an argument schema and nothing
else — no `side_effect`, `requires_authorization`, `destructive`,
`timeout_seconds`, `executor`, `re_executable` or `capability_digest`.

## 8. Resource bounds — who owns which

| Bound | Owner | Why there |
|---|---|---|
| capability name length, charset | `ToolSpec` admission | a property of the capability |
| `timeout_seconds` range (0.001–300) | `ToolSpec` admission | the structural maximum any capability may declare |
| retry budget | `RunContext` | a property of the run, not the tool |
| result count ceiling | `RunContext.max_results_ceiling` | per-run policy |
| file/listing/path/result-size ceilings | `RunContext.filesystem` | per-run policy, enforced by the executor |
| argument serialized size | `records.MAX_ARGUMENTS_BYTES` | a persistence bound |
| record and event-count ceilings | `records` | persistence bounds |
| operator decision ceiling | `records` | control-plane bound |

Nothing was duplicated. The one new bound — the timeout range — had no owner at
all, which is how `-5` was admissible.

## 9. Audit and data flow

`ExecutionAuthorized` gains exactly one field, `capability_digest`, which is a
hash. Nothing else about a capability enters durable state.

Still never persisted: credentials, API keys, authorization headers, raw
prompts, model reasoning, model responses, tool result payloads, physical
filesystem roots, exception text, unrestricted operator text.

Verified with **runtime sentinels through the real data flow**, not by grepping
source. A workspace directory whose name *is* the sentinel is read by the real
filesystem capability, and the sentinel is then sought in the result, the
events, the model payload, the capability digests and the model-visible tool
descriptions. A sentinel API key is carried by the real config through the real
adapter, and sought in the transport requests, the journal, the events, the
result, the config's `repr` and the digests. A positive control proves the
probe can detect a leak when one exists.

## 10. Future side-effecting capability admission

No side-effecting capability is implemented, and no escape hatch was created.
What exists is the contract one must satisfy. Fifteen requirements, each mapped
to the mechanism that now represents it:

| # | Requirement | Where it lives today |
|---|---|---|
| 1 | affected resource | the abstract root id / argument schema |
| 2 | required grant | `RunContext.authorized_tools` + `requires_authorization` |
| 3 | applicable policy | `evaluate_policy`, per-run ceilings |
| 4 | argument constraints | `args_schema`, frozen, `extra="forbid"` |
| 5 | resource limits | `RunContext` for per-run, admission for structural |
| 6 | side-effect classification | `SideEffect`, three-valued, default `MUTATING` |
| 7 | idempotency | `SideEffect.IDEMPOTENT`, distinct from `NONE` |
| 8 | retry safety | `re_executable`, gating the controller's retry branch |
| 9 | execution-unknown behaviour | `side_effect_free` → `plan_recovery` disposition |
| 10 | legal operator actions | `recovery._available_actions`, per disposition |
| 11 | durable evidence | `ExecutionAuthorized` / `ExecutionCompleted` + digest |
| 12 | secret/data-flow boundaries | the sanitization rules, sentinel-tested |
| 13 | result schema | `result_schema`, validated in VERIFY |
| 14 | execution identity | `derive_execution_id` over canonical arguments |
| 15 | definition-change behaviour | `capability_digest`, fatal on mismatch |

**All fifteen are now representable.** Before this milestone, 6, 7, 8 and 15
were not: the classification was a boolean that conflated 6 and 7, retry
ignored 8 entirely, and 15 had no mechanism at all.

A `destructive` capability additionally cannot be admitted unless it requires
authorization **and** is classified `MUTATING` — a capability that destroys
something while claiming repeating it is free is describing two different
tools.

## 11. What was deliberately not changed

`policy.authorize` is untouched. The incoherent capability it would have
approved is now inadmissible, which is the right layer: the gate is a
Milestone 1 invariant, and adding a special case to it would have made the gate
responsible for the registry's failure to check.

The state machine, the model boundary, filesystem containment, the transport
boundary, journal semantics, recovery semantics, operator approval semantics,
terminality, replay and deterministic fingerprinting are all unchanged. The
Milestone 6 §22.8 deviation stands as documented and was not revisited.

## 12. Proven, assumed, unproven, deferred

**Proven** — by executable tests in this commit: the admission matrix (24 cases
refused at `admit` *and* at the registry, each by stable slug); a replaced spec
is re-checked rather than carried forward; duplicate names are refused rather
than replaced; the registry map cannot be written through, rebound or deleted,
and its views are read-only; no `ToolSpec` field can be reassigned or added;
the derived properties cannot be assigned and cannot disagree with the
classification; the schema classes remain mutable (asserted, not denied); a
mutated schema changes the capability digest and the registry recomputes rather
than caches; in-run retry produces 3, 3 and 1 physical effects for `NONE`,
`IDEMPOTENT` and `MUTATING`; a pre-execution rejection still retries for every
classification; cases D, E, F, G and H behave as tabulated; a journal without a
digest is reported unverifiable rather than verified; an executor can reach no
authority from its arguments and cannot widen its result past verification; ten
hostile result shapes fail verification; instruction-shaped result content stays
data; eighteen authority-named fields are refused in both positions; the
model-visible surface carries no capability metadata; capability-contract
operations are byte-identical over 100 repetitions; sentinel roots, credentials,
execution identities, plan identities and operator reasons do not reach the
surfaces that must not carry them.

**Proven by mutation** — eleven deliberate breaks of the real implementation
(admission gate removed, `MappingProxyType` reverted to a dict, attribute guard
removed, retry gate forced open, `re_executable` collapsed, `side_effect_free`
decoupled, digest check removed, coherence rule removed, name validation
removed, executor-protocol check removed, capability metadata leaked into the
model surface). Every one was caught by a failing test; the source was restored
byte-for-byte and the full suite re-run green.

**Assumed** — everything Milestones 5 and 6 assumed (`fsync` reaches stable
storage, appends are not reordered across it, advisory `flock` is honoured,
POSIX, and that whoever can call the operator API is the operator), plus one
new assumption stated plainly: **that no code in the process deliberately
circumvents the registry's guards.** `object.__setattr__` defeats them, as it
defeats any in-process guard.

**Unproven** — that a capability's schemas cannot be mutated (they can; the
digest detects it, and only where a digest was recorded); that the digest
detects an executor swap (it does not, by design); that a digest is a tamper
seal (it is not — no key exists); exactly-once execution; that the three-value
classification is sufficient for capabilities that do not yet exist — it is
sufficient for the questions the controller currently asks, and the first real
side-effecting capability is the test of that. Live LocalAI inference remains
unobserved; nothing in this milestone changed or needed that.

**Deferred** — capability versioning (no need demonstrated); a general
side-effecting capability (this milestone deliberately builds the admission
contract instead); authenticated operator identity; a CLI; and everything in
§2's exclusion list.
