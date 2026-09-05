# Local AI Agent — Agent Instructions

This is a **separate Python subproject** inside the LocalAI repository. It does not
build, import, or depend on LocalAI's Go code, and LocalAI does not depend on it.
Work here from `local-agent/`, not the repository root.

Human and machine readers alike: the specification of record is the reference
package, summarised in [`docs/milestone-1-decisions.md`](docs/milestone-1-decisions.md)
and [`docs/milestone-2-decisions.md`](docs/milestone-2-decisions.md). Where this
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

Milestone 1 (deterministic control plane) and Milestone 2 (read-only filesystem
capability) are both complete and gated by CI.

**In scope:** state machine, typed contracts, tool registry, authorization,
policy, retry budget, parser boundary, fake model adapter, audit events, the
`workspace.read` / `workspace.list` capability, and tests.

**Explicitly out of scope until a later milestone opens it:** writes of any
kind, shell or subprocess execution, Playwright or any browser, network access,
MCP, Docker code execution, Qdrant, SQLite persistence, Gemma, llama.cpp, and
OS-level sandboxing. `tests/test_architecture.py` enforces this by parsing the
package's own AST — adding `import subprocess` fails the suite, it does not
merely violate a convention.

**The filesystem grant is per module.** `executors/workspace_fs.py` is the only
production file allowed to import `pathlib` or touch a disk. That grant lives in
`MODULE_IMPORT_GRANTS` in the architecture test and is mirrored in
`.claude/hooks/milestone_scope_guard.py`; keep the two in step. Never widen the
global allowlist to solve a one-module need — a global widening is exactly how
the controller would quietly acquire filesystem access later.

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
      executors/
        file_search.py  Milestone 1 deterministic fake
        workspace_fs.py read-only filesystem — the sole holder of a disk grant
    tests/              unit, adversarial, authority, filesystem, determinism,
                        architecture

## A note on enforcement

`CLAUDE.md` is context, not configuration: it informs an assistant, it does not
constrain one. The layers that actually hold are the frozen types, the
transition table, the AST-level architecture tests, the pinned dependency set,
and code review. Treat this file as the explanation, and the test suite as the
enforcement.
