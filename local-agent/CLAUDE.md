# Local AI Agent — Agent Instructions

This is a **separate Python subproject** inside the LocalAI repository. It does not
build, import, or depend on LocalAI's Go code, and LocalAI does not depend on it.
Work here from `local-agent/`, not the repository root.

Human and machine readers alike: the specification of record is the reference
package, summarised in [`docs/milestone-1-decisions.md`](docs/milestone-1-decisions.md)
[`docs/milestone-2-decisions.md`](docs/milestone-2-decisions.md),
[`docs/milestone-3-decisions.md`](docs/milestone-3-decisions.md),
[`docs/milestone-4-decisions.md`](docs/milestone-4-decisions.md),
[`docs/milestone-5-decisions.md`](docs/milestone-5-decisions.md), and
[`docs/milestone-6-decisions.md`](docs/milestone-6-decisions.md). Where this
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
state and crash recovery) and 6 (operator-controlled recovery) are complete and
gated by CI.

**Milestone 4 is hardened but not yet observed live.** No LocalAI instance was
reachable where it was written, so the four live scenarios are implemented and
their skip/fail semantics verified, but no live exchange has been seen. Do not
describe the live path as proven until someone runs `pytest -m live` against a
real instance. See `docs/milestone-4-decisions.md` §1 and §8.

**In scope:** state machine, typed contracts, tool registry, authorization,
policy, retry budget, parser boundary, audit events, the `workspace.read` /
`workspace.list` capability, the LocalAI model adapter and its transport, the
durable run journal with its recovery and replay, the operator control plane
(inspection, decisions, approved resume, abort), and tests.

**Explicitly out of scope until a later milestone opens it:** writes to a
workspace, shell or subprocess execution, Playwright or any browser, network
access outside the model transport, MCP, Docker code execution, Qdrant, SQLite,
Gemma, llama.cpp, OS-level sandboxing, distributed coordination, automatic
*unattended* resumption, authenticated operator identity, and a CLI binary.
`tests/test_architecture.py` enforces this by parsing the package's own AST —
adding `import subprocess` fails the suite, it does not merely violate a
convention.

**Capability grants are per module.** `executors/workspace_fs.py` and
`persistence/journal.py` are the only production files allowed to touch a disk,
and `transports/http.py` is the only one allowed a network import. All grants
live in `MODULE_IMPORT_GRANTS` in the architecture test and are mirrored in
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
      registry.py       ToolSpec, ToolRegistry, ToolExecutor protocol
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
      persistence/
        records.py      versioned durable record contracts (pure, no I/O)
        journal.py      append-only journal — sole holder of a write grant
      transports/
        http.py         sole holder of a network grant
    tests/              unit, adversarial, authority, filesystem, model,
                        transport, persistence, recovery, operator,
                        determinism, architecture
      live_support.py   env conventions + gate semantics (test layer only)
      test_live_localai.py     opt-in live scenarios (marked `live`)
      test_live_boundary.py    deterministic proof of the gate semantics

## A note on enforcement

`CLAUDE.md` is context, not configuration: it informs an assistant, it does not
constrain one. The layers that actually hold are the frozen types, the
transition table, the AST-level architecture tests, the pinned dependency set,
and code review. Treat this file as the explanation, and the test suite as the
enforcement.
