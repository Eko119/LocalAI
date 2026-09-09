# Milestone 6 — Operator-Controlled Recovery, Run Inspection, and Auditable Resume

Milestone 5 left every ambiguous run stranded on purpose. `plan_recovery`
produced a plan, `requires_operator` said a human had to decide, and nothing
in the system could act on that decision. This milestone closes the loop
without handing the operator a general execution mechanism.

The whole design follows from one sentence:

> **The operator may say "I approve this exact controller-generated plan".
> The operator may not say "execute this".**

Everything below is either an implementation of that sentence or an honest
account of where it cost something.

---

## 1. Operator authority

The operator is trusted in the *product* model and untrusted as a *source of
values*. Both halves are load-bearing.

Trusted, because refusing anyone the ability to decide would leave every
`execution_unknown` run stranded forever — the controller genuinely cannot
know whether an ambiguous side effect occurred, and pretending otherwise is
how a system ends up guessing.

Untrusted, because an operator decision arrives as data. Every field is
validated against something the controller derived for itself, moments
earlier, from the journal. The decision's entire role is to *match*.

What makes this structural rather than procedural is the shape of
`OperatorDecision`. It has seven fields:

```
schema_version  run_id  plan_id  action  decision_sequence
reason_code     expected_execution_id
```

There is no `tool`, no `arguments`, no `max_attempts`, no `root_id`, no
`side_effect_free`, no `authorized_tools`, and no executor selector. With
`extra="forbid"`, adding one in transit is a schema violation. So the threat
model's prohibitions — "may not select a replacement tool", "may not replace
canonical arguments", "may not increase the retry budget" — are not rules
someone has to remember to check. They are sentences the type has no
vocabulary for, and `test_a_decision_has_no_vocabulary_for_execution_details`
walks eleven of them.

The three identity fields are *bindings*, not selections. `expected_execution_id`
is the one place an execution identity appears, and the decision must match
the controller's own value rather than choosing it.

## 2. The recovery plan

The controller generates the plan. The operator reads one and picks an action
from `available_actions`; they never construct one and never edit one.

A plan is **content-addressed**, using the same technique as execution
identity:

```
plan_id = sha256(canonical_json({schema_version, run_id, disposition,
                                 reason_code, tool, step_id, attempt,
                                 arguments, execution_id, side_effect_free,
                                 max_attempts, execution_status,
                                 terminal_*, available_actions,
                                 decisions_recorded, next_decision_sequence,
                                 last_action, authorization_valid}))[:32]
```

Two consequences follow, and neither is a rule anyone can forget to apply:

* an operator cannot submit a plan of their own construction and have it
  believed, because the controller re-derives the id from the journal every
  time and compares;
* **recording any decision changes the plan's identity**, because
  `decisions_recorded` is in the material. An approval therefore cannot be
  replayed against the plan that produced it, let alone a later one.

A plan also carries `authorization_valid`, computed by running the *real*
`authorize` and `evaluate_policy` gates against the re-validated arguments —
not a remembered verdict, and not a reimplementation.
`test_recovery_does_not_bypass_the_gates_it_reports_on` asserts against the
module's own source that the real gate functions are called, because a
reimplementation would drift and offer resumes that EXECUTE would refuse.

## 3. Available actions, and two deliberate refusals

`OperatorAction` is a closed set: `resume`, `abort`, `terminalize`,
`reject_recovery`, `acknowledge`. An unknown action has no code path, not
merely no permission — it fails at the schema, before any dispatch.

`inspect` is deliberately absent from that set: inspection persists nothing
and decides nothing, so it is a read on the operator API rather than a durable
decision.

The action table is exhaustive over the disposition space, and two of its
entries are restrictions worth naming:

| Disposition | Actions offered |
|---|---|
| `terminal` | *(none)* |
| `no_execution_authorized` | abort, terminalize, acknowledge, reject_recovery |
| `execution_completed` | abort, terminalize, acknowledge, reject_recovery |
| `execution_pending_repeatable` (+ gates pass) | **resume**, abort, terminalize, acknowledge, reject_recovery |
| `execution_unknown` | abort, terminalize, acknowledge, reject_recovery |

**`execution_unknown` is never offered a resume.** The tool is not declared
side-effect free and the journal cannot say whether the effect happened, so
re-running might duplicate a real side effect. Letting the operator overrule
that would be precisely the "operator changes `side_effect_free`" move the
threat model forbids — a human asserting a fact the controller cannot verify.

The cost is real and worth stating plainly: an operator who *knows* the effect
did not happen still cannot resume, and must start a new run instead. That is
the price of never letting an unverifiable assertion reach an executor, and it
is the right trade for a system whose entire premise is that authority lives in
deterministic code.

**`execution_completed` is never offered a resume** either. The physical call
finished, but the journal deliberately never stored the result (Milestone 5,
§16), so the run cannot be verified without executing a second time. The honest
disposition is that the run cannot be completed, not that it can be redone.

## 4. Approval binding

`validate_decision(decision, plan)` compares six things, and the plan id is the
one that does most of the work. Because a plan's id covers the disposition,
the tool, the canonical arguments, the execution identity, the budget, the
available actions, and the decision count, that single comparison rejects:

* a stale approval (the plan moved on);
* a cross-plan approval;
* a replayed approval (recording it changed the plan);
* an approval made before the `ToolSpec` or the policy changed;
* a plan the operator invented.

`decision_sequence` adds the duplicate-resume bound: it must equal the
controller-derived `next_decision_sequence`, so a single approval authorizes at
most one resume attempt.

## 5. Immediate revalidation

**An approval is a statement about a moment, and the moment ends the instant
the decision is recorded.** `_revalidate_recovery` therefore runs *after* the
decision is durable and *before* any executor, and re-establishes every fact
from scratch:

1. re-read the journal and re-derive the plan;
2. confirm the run id, budget, disposition, execution identity, tool,
   arguments, attempt, step id and `side_effect_free` are unchanged;
3. confirm the decision was recorded **exactly once** and is the latest;
4. for `resume` only: re-resolve the `ToolSpec` from the live registry,
   re-validate the arguments against its *current* schema, re-run `authorize`
   and `evaluate_policy`, and re-derive the execution identity from the tool
   and arguments actually about to run.

Step 4 is not redundant with step 2. The controller trusts the approval for
exactly one thing — that a human said yes to this plan — and re-establishes
everything else.

`test_a_registry_swapped_after_approval_is_caught_before_the_executor` proves
this reaches further than the binding check: a `MutatingJournal` empties the
registry at the instant the decision becomes durable, and the resume is refused
with zero executions.

## 6. The safe resume path

There is **no recovery executor**, and that is the point: a second execution
path would be a second place for a gate to be forgotten.

`Controller.run` and `Controller.recover` share one attempt loop, `_loop`. The
only difference is a `_ResumeSeed`: when present, the first iteration takes its
operation from the journal instead of the model. Everything after that branch —
AUTHORIZE, POLICY_CHECK, EXECUTE, VERIFY, RESPOND, TERMINAL — is the same code
a fresh run executes.

A resumed run's state trace is therefore identical to an ordinary one:

```
RECEIVE CLASSIFY GENERATE PARSE VALIDATE AUTHORIZE POLICY_CHECK EXECUTE VERIFY RESPOND TERMINAL
```

The states are *walked* rather than skipped because the run really did pass
through them before it crashed — this is the same run continuing, not a new one
jumping gates. It also matches what `replay` already reconstructs from an
`ExecutionAuthorized` record, so the two views agree. **No transition-table edge
was added**, so Milestone 1's "the model cannot invent a state" property is
untouched.

Resuming does **not** write a second `ExecutionAuthorized`. The write-ahead
record already on disk is still the authorization; writing another would forge
one the controller never made, and recovery would reject the journal for it. So
a recovered run ends with exactly one authorization, one execution identity,
and one completion.

`messages` is supplied by the caller because the journal deliberately never
stored the conversation (Milestone 5 forbids persisting prompts). A resume that
succeeds never uses it; a resume whose execution fails and still has budget
continues into an ordinary retry, which does need something to send.

## 7. Recovery transparency

Successful recovery does not tell the model that recovery happened. Nothing
injects a plan, a decision, an execution identity, a reason code, lock
metadata, policy internals, or an operator identity into model-facing context —
because nothing on the recovery path constructs a model-facing payload at all.

`test_recovery_is_semantically_transparent` states the property as an
equivalence between two paths:

* **Path A** — an ordinary uninterrupted run;
* **Path B** — crash → plan → approval → resume.

Both produce the same verified semantic result, the same
`ControllerTerminal`, and the same state trace.

The journals differ, and deliberately so: Path B carries an extra
`operator_decision` record. Hiding that would defeat the audit, so
`test_the_recovered_journal_differs_only_by_its_audit_records` asserts the
difference is *exactly* that one record and nothing else.

### A deviation worth naming

The milestone's §22 asks the successful-resume test to end with "normal
controller continuation requests another model generation". This controller
does not have that shape: since Milestone 1 a run is a single tool call, and
`RESPOND → TERMINAL` is the only edge out of a successful execution. Giving the
model the tool result and looping would be a redesign of the run contract, not
an extension of it, and it would change every existing test — a Milestone 1–5
invariant, which §32 lists as a stop condition rather than something to work
around.

So the property is tested where it genuinely exists. A resumed execution that
*fails* continues into an ordinary retry, which does call the model, and
`test_a_resumed_run_that_continues_sends_the_model_nothing_about_recovery`
asserts that the model is asked again and receives only the ordinary sanitized
`ToolFeedback` — an error code and a message — with sentinel values for the plan
id, the execution id and the operator reason code all absent. That is the leak
question §22 exists to answer, asked at the point where a leak could actually
occur.

## 8. Abort

An abort is a terminal controller decision. It is **not** a tool failure, and
the code synthesises nothing to make it look like one: no `ToolExecutionError`,
no `tool_failed`, no fabricated result, no pseudo-result in model context, and
no further generation.

```
RECOVERY_REQUIRED → operator abort → persist decision → ABORTED → terminal
```

After an abort: no executor, no retry, no new approval, no model generation, no
fabricated completion, no resurrection. `test_after_an_abort_nothing_can_execute_retry_or_be_approved`
asserts each of those separately.

`RunTerminal.status` gained `"aborted"` alongside `"succeeded"` and `"failed"`.
Collapsing an abort into a failure would lose the difference between "this went
wrong" and "a human stopped it" in the only record that survives the process.
`terminalize` is kept distinct too: it records `failed` with
`OPERATOR_TERMINALIZED`, so the audit can tell "operator stopped a live run"
from "operator closed an unrecoverable one".

## 9. Ambiguity is preserved, never rewritten

This is the subtlest requirement in the milestone and the easiest to get
cosmetically wrong.

Abort means *the controller will perform no further execution for this run*. It
does **not** mean *the previous execution did not happen*. After an
`execution_unknown` run is aborted, three facts remain separately visible on
disk:

* an `execution_authorized` record with **no** matching `execution_completed`
  — the ambiguity itself, untouched;
* an `operator_decision` recording the abort;
* a `run_terminal` with status `aborted`.

Nothing rewrites the first into a failure or a non-execution for tidiness.
`test_an_abort_preserves_execution_ambiguity` asserts all three, and the
replay of that journal reports `executions_completed == 0` with
`terminal_status == "aborted"` — distinguishable from every other ending.

## 10. Terminal immutability

Once a run reaches a terminal state it cannot be resurrected, whatever the
status. `_available_actions` returns `()` for `terminal` before any other
consideration, so there is no action to take; `validate_decision` additionally
refuses with `run_is_terminal` so the reason names the real cause. A decision
record appearing *after* a terminal in the journal is refused by Milestone 5's
existing `journal_record_after_terminal` check.

`test_every_terminal_status_is_equally_final` walks all three statuses, and
`test_no_action_is_accepted_on_a_terminal_run` walks all four actions.

## 11. Audit records

One new durable record type:

```
OperatorDecisionRecorded:
  type  schema_version  run_id  decision_sequence  action
  plan_id  expected_execution_id  reason_code
```

It is durable because it is the evidence that a human was asked and answered,
and the thing that stops one approval being used twice. It is explicitly **not**
an authorization: the controller re-derives every execution fact for itself and
re-runs every gate before acting, so this record grants nothing on its own.

Not persisted: API keys, authorization headers, credentials, physical
filesystem roots, model reasoning, model responses, raw prompts, stack traces,
unrestricted operator text, secrets, environment values.

`reason_code` is a **stable slug**, constrained to `^[a-z][a-z0-9_]{0,63}$`.
The charset is the enforcement: with no spaces, no punctuation and no
uppercase, the field structurally cannot carry a sentence, an instruction, or a
prompt-injection payload. That is a stronger property than filtering one, and
`test_operator_text_cannot_become_an_instruction_channel` walks seven attempts.

## 12. Operator identity — what this project does not claim

**The project has no authentication model, and this milestone does not invent
one.** There is no user store, no session, no signature, no capability token,
and nothing in Milestones 1–5 that could attribute an action to a person.

So `OperatorDecisionRecorded` has no `operator` field. Adding an unauthenticated
one would record a *claim* while implying a *verified fact*, which is worse
than recording nothing — an audit trail that says "alice approved this" when
anyone with write access could have typed `alice` is actively misleading.

Stated plainly: **the operator interface is a trusted local control surface.**
Anyone who can call these APIs and write this journal is the operator. If that
assumption does not hold in a deployment, the missing layer is authentication,
and it belongs in a milestone that opens it.

## 13. Concurrency

No new locking was invented. Milestone 5's advisory `flock` still means two
live journal holders cannot both recover a run, and
`test_two_live_journal_holders_cannot_both_recover` pins it.

Above that, the decision sequence bounds duplicate resumes: the first attempt
records a decision, which changes the plan's identity, so a second controller
holding the same approval is refused.
`test_two_sequential_resume_attempts_execute_at_most_once` measures one
executor call, one completion record, and one refusal.

**This is not exactly-once, and is not described as such.** The guarantee is
that a single approval authorizes a single attempt. Milestone 5's semantics are
unchanged: `side_effect_free` tools are at-least-once and observationally
equivalent to exactly-once because of the tool; everything else is at-most-once
with an explicit unknown.

## 14. The operator interface: a typed API, not a CLI

§16 permits reusing an existing CLI/API mechanism. There is none — this project
has no entry point, no `__main__`, no `[project.scripts]`, and no argument
parser anywhere. The operator surface is therefore a typed in-process API:

* `inspect_run(records, registry, run_context) -> RunInspection`
* `render_inspection(inspection) -> str` — canonical JSON, deterministic
* `plan_recovery(...) -> RecoveryPlan`
* `validate_decision(decision, plan) -> None`
* `Controller.recover(run_context, decision, messages) -> RecoveryOutcome`

**A CLI binary was deliberately not added.** It would need `sys`, `argparse`
and `pathlib` grants in production code purely to parse arguments and print —
three new capability surfaces for a presentation layer, in a milestone whose
own §0 says "CLI/API surface only where needed to expose these operations
safely". Every substantive §16 requirement is met by the API: all input is
validated, all types are schemas, no executor is reachable, no policy is
bypassed, no secret or physical root or model text appears, and
`render_inspection` is deterministic machine-readable output. A CLI over this
API is a small, safe, additive change whenever someone wants one; it is listed
as deferred work rather than smuggled in.

## 15. Resource limits

| Surface | Bound |
|---|---|
| operator decisions per run | 20 (`MAX_OPERATOR_DECISIONS_PER_RUN`) |
| `decision_sequence` | 1..20, at the record *and* the decision schema |
| `reason_code` | 64 chars, `^[a-z][a-z0-9_]{0,63}$` |
| `plan_id` / `expected_execution_id` | exactly 32 chars |
| plan arguments | Milestone 5's `MAX_ARGUMENTS_BYTES` (16 KiB) |
| inspection output | bounded by the record and event ceilings it projects |

Once the decision ceiling is reached a run offers no actions at all — the
control plane is bounded the same way every other durable surface is.

## 16. Proven, assumed, not guaranteed, deferred

**Proven** — by executable tests in this commit: plan identity is reproducible
and changes with every recorded decision; an approval cannot be replayed
against any plan including the one that produced it; a decision cannot express
a tool, arguments, a budget or an executor; unknown actions and injected
operator text fail at the schema; `execution_unknown` and `execution_completed`
are never offered a resume; every terminal status refuses every action; the
thirteen crash windows leave the states described; a resume re-executes the
original tool with the original canonical arguments under the original identity
and the ordinary gates; a registry emptied mid-flight is caught before any
executor; abort calls no executor and no model and fabricates nothing; abort
preserves the authorization-without-completion ambiguity; two live journal
holders cannot both recover; one approval authorizes one attempt; recovery
performs zero model calls; sentinel plan ids, execution ids and reason codes do
not appear in anything the model was sent; Path A and Path B agree on result,
terminal and state trace; replay of a recovered run still executes nothing;
seven operator scenarios fingerprint identically over 100 repetitions each.

**Assumed** — everything Milestone 5 assumed (`fsync` reaches stable storage,
appends are not reordered across it, advisory `flock` is honoured, POSIX), plus
one new assumption stated in §12: that whoever can call the operator API and
write the journal is the operator. There is no authentication to verify it.

**Not guaranteed** — exactly-once execution, in general or under recovery;
protection against an attacker who can rewrite the journal into a fully
self-consistent alternative history; multi-host coordination; recovery of a run
whose grants or `ToolSpec` legitimately changed (that fails closed rather than
adapting); reconstruction of a conversation the journal deliberately never
stored.

**Deferred** — a CLI over the operator API (§14); authenticated operator
identity (§12); resuming an `execution_unknown` execution under any evidence
the controller cannot itself verify (§3); automatic unattended resumption,
which remains explicitly out of scope; and everything in §0's exclusion list.
