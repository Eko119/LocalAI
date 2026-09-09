# Local AI Agent — Agent Instructions

This is a **separate Python subproject** inside the LocalAI repository. It does not
build, import, or depend on LocalAI's Go code, and LocalAI does not depend on it.
Work here from `local-agent/`, not the repository root.

Human and machine readers alike: the specification of record is the reference
package, summarised in [`docs/milestone-1-decisions.md`](docs/milestone-1-decisions.md)
[`docs/milestone-2-decisions.md`](docs/milestone-2-decisions.md),
[`docs/milestone-3-decisions.md`](docs/milestone-3-decisions.md),
[`docs/milestone-4-decisions.md`](docs/milestone-4-decisions.md),
[`docs/milestone-5-decisions.md`](docs/milestone-5-decisions.md),
[`docs/milestone-6-decisions.md`](docs/milestone-6-decisions.md),
[`docs/milestone-7-decisions.md`](docs/milestone-7-decisions.md),
[`docs/milestone-8-decisions.md`](docs/milestone-8-decisions.md), and
[`docs/milestone-9-decisions.md`](docs/milestone-9-decisions.md). Where this
file and that package disagree, the package wins, and the disagreement should be
written down rather than resolved silently.

## The one idea

    MODEL PROPOSES · CONTROLLER DECIDES · POLICY AUTHORIZES
    EXECUTOR ACTS  · VERIFIER CHECKS   · PERSISTENCE RECORDS

The LLM is an untrusted probabilistic component. Every operational decision —
which state comes next, whether a tool runs, how many attempts remain — belongs
to deterministic code. If a change would let model output influence any of
those, it is wrong regardless of how well it works.

## Current milestone

Milestones 1 (deterministic control plane), 2 (read-only filesystem),
3 (production model adapter), 4 (live integration hardening), 5 (durable run
state and crash recovery), 6 (operator-controlled recovery), 7 (the capability
contract), 8 (the constrained artifact writer) and 9 (the first
non-re-executable mutation) are complete and gated by CI.

**Milestone 4 is hardened but not yet observed live.** No LocalAI instance was
reachable where it was written, so the four live scenarios are implemented and
their skip/fail semantics verified, but no live exchange has been seen. Do not
describe the live path as proven until someone runs `pytest -m live` against a
real instance. See `docs/milestone-4-decisions.md` §1 and §8.

**In scope:** state machine, typed contracts, tool registry, authorization,
policy, retry budget, parser boundary, audit events, the `workspace.read` /
`workspace.list` capability, the LocalAI model adapter and its transport, the
durable run journal with its recovery and replay, the operator control plane
(inspection, decisions, approved resume, abort), the capability admission
contract, the `workspace.write` and `workspace.append` capabilities, and
tests.

**Explicitly out of scope until a later milestone opens it:** every filesystem
mutation other than replacing one regular file or appending to one — delete,
rename, mkdir, chmod, copy — shell or subprocess execution, Playwright or any
browser, network access outside the model transport, MCP, Docker code
execution, Qdrant, SQLite,
Gemma, llama.cpp, OS-level sandboxing, distributed coordination, automatic
*unattended* resumption, authenticated operator identity, and a CLI binary.
`tests/test_architecture.py` enforces this by parsing the package's own AST —
adding `import subprocess` fails the suite, it does not merely violate a
convention.

**Capability grants are per module.** `executors/workspace_fs.py`,
`executors/workspace_write.py`, `executors/workspace_append.py` and
`persistence/journal.py` are the only production files allowed to touch a disk,
and `transports/http.py` is the only one allowed a network import. Reading a
workspace and writing one are separate
grants held by separate modules on purpose: `workspace_fs.py` is *provably*
read-only — its AST is asserted to call no mutating method and to open files
only in `"rb"` — so putting a writer beside it would have meant weakening those
assertions rather than adding to them. All grants live in
`MODULE_IMPORT_GRANTS` in the architecture test and are mirrored in
`.claude/hooks/milestone_scope_guard.py`; keep the two in step. Never widen the
global allowlist to solve a one-module need — a global widening is exactly how
the controller would quietly acquire filesystem or network access later.

**The operator decides; the controller acts.** An operator may say "I approve
this exact controller-generated plan" and may not say "execute this". The
difference is structural: `OperatorDecision` has no field for a tool, arguments,
a budget, or an executor, and `extra="forbid"` makes adding one a schema
violation. A plan is content-addressed, so recording any decision changes its
identity and no approval can be replayed. Everything is re-validated from
scratch — registry, argument schema, both gates, execution identity — *after*
the decision is durable and *before* any executor runs. Never add a `--force`,
`--unsafe`, `--bypass` or equivalent; there is no generic admin execution path
and adding one would undo this milestone entirely.

**A capability is admitted, never merely constructed.** `ToolSpec` is a plain
frozen dataclass and dataclasses do not validate, so construction proves
nothing. `ToolRegistry` runs `admit` on every entry, every time — there is
deliberately no "already checked" marker, because a marker is a field and
`dataclasses.replace` copies fields. Admission checks the name, both schemas,
the executor protocol, the timeout range, and the coherence rules; a
`destructive` capability that does not require authorization would skip the
grant check entirely, so it cannot exist.

**Side-effect, retry and idempotency are three questions, not one.**
`SideEffect` is `NONE` / `IDEMPOTENT` / `MUTATING`, defaulting to `MUTATING`.
`side_effect_free` (did anything happen?) and `re_executable` (is repeating
safe?) are *derived* properties, so they cannot drift. Never collapse them back
into a boolean, and never equate `side_effect_free` with retryable — an
idempotent capability is safe to retry while emphatically having had an effect.
The controller's retry branch consults `re_executable`; before Milestone 7 it
did not, and a failing `MUTATING` capability ran once per attempt.

**A side effect is governed, not merely permitted.** `workspace.write` replaces
one regular file beneath one authorized root and does nothing else — no delete,
no rename, no mkdir, no chmod, no append, no mode selector. Containment is the
*existing* helper: the destination's parent is resolved strictly through
`_resolve_within_root`, which both proves containment and makes a missing
parent a refusal, and the final component is opened with `O_NOFOLLOW` so the
symlink check is unraceable. Two facts that look like tidiness and are not:
`O_NOFOLLOW` guards only the last component, so the strict parent resolution is
what stops a symlinked directory escaping; and the non-regular-destination
check has no second mechanism behind it, because opening a FIFO without
`O_NONBLOCK` blocks forever and no timeout is enforced anywhere. Never widen
this into a generic filesystem seam — a new operation must mean a new module, a
new schema, a new registry entry and new tests.

**Four axes, and Milestone 9 is where they stop correlating.**
`side_effect_free` asks *could anything have happened*; `re_executable` asks
*is repeating safe*; the journal holds *what is actually known*; the
disposition states *what conclusion is justified*. Every capability before
`workspace.append` made at least two of those agree, so nothing had ever tested
that they are genuinely separate. Never substitute one for another because they
happen to align: `side_effect_free == False` must not imply `re_executable ==
False`, and `re_executable == False` must never be implemented by pretending
`side_effect_free == True`.

**`workspace.append` is `MUTATING`, measured rather than declared.** Against
Milestone 8's own written bound — idempotent with respect to the destination's
existence and content — appending fails it: one request yields `seed\nentry\n`
and two yield `seed\nentry\nentry\n`. It needed no new authority to build,
only one flag exchanged (`O_APPEND` in, `O_CREAT` and `O_TRUNC` out), which is
why it is the *smallest* capability that reaches the fourth corner rather than
merely the most obviously non-idempotent one. Dropping `O_CREAT` is what makes
"never creates a file" a property of the flags instead of a guard.

**Unknown is neither failed nor succeeded, and an operator ends the run rather
than the uncertainty.** A crash between the executor and the completion record
leaves `execution_unknown`; a *clean* failure is different, because it records
`ExecutionCompleted(status="failed")` and closes the window. When resume is
withheld, `abort` and `terminalize` remain available and are pure control-plane
transitions — no executor, no model, no fabricated completion — so the
authorization with no completion stays on disk beside the terminal record.
Milestone 9 required no new operator vocabulary; adding a synonym for
`terminalize` would have created a second terminal path to keep in step.

**A capability is content-addressed because immutability cannot reach its
schemas.** `args_schema` and `result_schema` are classes and Python classes are
mutable — measured, not assumed. `capability_digest` covers both schemas plus
the declared properties and is recorded on `ExecutionAuthorized`, so a
definition that changed after authorization is detected by recovery. It detects
drift, not tampering; a record with no digest is reported `capability_verified
= False` rather than treated as verified.

**Recovery never calls the model.** Not to plan, not to validate, not to decide
whether resuming is safe. A model that could influence recovery would be an
untrusted component deciding its own containment.

**Abort is not a tool failure.** It synthesises no `ToolExecutionError`, no
completion record, no result, and no model turn — and it never rewrites
`execution_unknown` into "did not happen". Abort means "no further execution",
never "the effect did not occur".

**The durable store records; it never decides.** A journal is a representation
of controller-owned state, not a second authority. Everything read back is
re-validated against the *live* registry and `RunContext` before it is
believed, and a record that disagrees is a fatal `RecoveryError`, never a
repair. Never add a code path that takes a budget, a grant, a tool identity, or
a state transition *from* the file — that is the exact shape of the mistake
this milestone exists to avoid.

**Live tests are opt-in, and the gate is a boundary.** Absent gate → SKIP.
Gate present but unusable → FAIL, never a silent skip. `pytest -q` must keep
working with LocalAI entirely offline, and CI must never depend on it.

**Never weaken TLS to make a test pass.** No `verify=False`, no unverified
context, no CA-bundle environment fiddling — in `src/` or in tests. A
self-signed instance is a deployment problem to solve, not a check to disable.

**The model is a proposal engine, never an authority.** A real adapter changes
nothing about that. Prose arrives on channels the parser never reads; a
proposal from the channel it does read still passes validation, authorization,
and policy. Never add a fallback that recovers a proposal from narrative.

## Rules

Detailed, enforceable rules live in `.claude/rules/`:

- [`architecture.md`](.claude/rules/architecture.md) — the authority pipeline and where each decision lives
- [`security.md`](.claude/rules/security.md) — trust boundaries, sanitization, what must never leak
- [`testing.md`](.claude/rules/testing.md) — what a change must prove before it lands

## Working commands

    uv sync --dev                  # create/refresh the project-local venv
    uv lock --check                # the lockfile is current
    uv run pytest -q               # full suite
    uv run ruff check .            # lint
    uv run ruff format --check .   # format
    uv run mypy src tests          # strict type check (pydantic plugin enabled)

All of these must pass before a change is considered done. They are the same
commands CI runs, in the same order.

## Layout

    src/local_agent/
      contracts.py      typed boundary models (frozen, extra="forbid")
      state_machine.py  State enum + explicit transition table
      registry.py       the capability contract — ToolSpec, SideEffect, admit,
                        capability_digest, the immutable ToolRegistry
      policy.py         RunContext (frozen authority) + the two gates
      controller.py     the orchestrator — the only component with authority
      model_adapter.py  ModelAdapter protocol + deterministic fake
      events.py         structured audit records
      wiring.py         trusted startup assembly
      model_config.py   frozen, validated model-service configuration
      model_transport.py transport seam + deterministic scripted transport
      model_service.py  production LocalAI adapter (OpenAI-compatible)
      recovery.py       crash-recovery planning + observational replay (pure)
      operator.py       operator control plane — decisions, binding, inspection
      executors/
        file_search.py  Milestone 1 deterministic fake
        workspace_fs.py read-only filesystem — sole holder of a read grant
        workspace_write.py the constrained artifact writer — sole holder of a
                        workspace replace grant
        workspace_append.py the first non-re-executable mutation — sole holder
                        of a workspace append grant
      persistence/
        records.py      versioned durable record contracts (pure, no I/O)
        journal.py      append-only journal — sole holder of the *durable
                        state* write grant
      transports/
        http.py         sole holder of a network grant
    tests/              unit, adversarial, authority, filesystem, model,
                        transport, persistence, recovery, operator,
                        capability, determinism, architecture
      live_support.py   env conventions + gate semantics (test layer only)
      test_live_localai.py     opt-in live scenarios (marked `live`)
      test_live_boundary.py    deterministic proof of the gate semantics

## A note on enforcement

`CLAUDE.md` is context, not configuration: it informs an assistant, it does not
constrain one. The layers that actually hold are the frozen types, the
transition table, the AST-level architecture tests, the pinned dependency set,
and code review. Treat this file as the explanation, and the test suite as the
enforcement.
