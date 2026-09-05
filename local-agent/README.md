# Local AI Agent — Deterministic Controller with Read-Only Filesystem

A deterministic control plane that treats an LLM as an untrusted proposal
engine. The model may suggest a tool call; nothing else about the model's
output has any authority.

    MODEL PROPOSES · CONTROLLER DECIDES · POLICY AUTHORIZES
    EXECUTOR ACTS  · VERIFIER CHECKS   · PERSISTENCE RECORDS

Milestone 1 proved, with executable tests, that a model producing arbitrary
malformed or hostile output cannot obtain unauthorized execution authority.
Milestone 2 gives the controller its first real external capability — read-only
filesystem access — without giving the model any filesystem authority at all:
it names an abstract root and a relative path, and never learns where either
one physically is.

## The pipeline

Every proposal walks the same path, and every stage can end the run:

    RAW MODEL OUTPUT
      -> PARSE            only the approved structured channel is read
      -> CANDIDATE        a typed envelope, nothing more
      -> SCHEMA VALIDATE  the tool's own Pydantic schema
      -> AUTHORIZE        does this run hold the grants?
      -> POLICY           do the operational rules allow this request?
      -> BUDGET           is an attempt left?  (default: 3, controller-owned)
      -> EXECUTE          the controller calls the executor; the model cannot
      -> VERIFY           the result is typed before anything reads it
      -> RESPOND

The stages are states in an explicit transition table. `Run.advance` is the
only way to change state and it consults that table, so a code path that tried
to reach EXECUTE without passing the gates raises rather than executes.

## Quick start

    uv sync --dev
    uv run pytest -q

The same four gates run in CI (`.github/workflows/local-agent.yml`, scoped to
`local-agent/**`):

    uv lock --check
    uv run pytest -q
    uv run ruff check .
    uv run ruff format --check .
    uv run mypy src tests

## Example

```python
import asyncio, json

from local_agent.contracts import ModelResponse
from local_agent.controller import Controller
from local_agent.model_adapter import ScriptedModelAdapter
from local_agent.policy import RunContext
from local_agent.wiring import build_default_registry

proposal = json.dumps(
    {
        "tool": "file_search",
        "arguments": {"query": "Jeep clutch notes", "root_id": "workspace"},
    }
)

controller = Controller(
    build_default_registry(),
    ScriptedModelAdapter((ModelResponse(structured_output=proposal),)),
)

outcome = asyncio.run(
    controller.run(RunContext(run_id="demo"), [{"role": "user", "content": "find them"}])
)

print(outcome.terminal)  # status='succeeded' attempts=1
print(outcome.result)  # status='success' data=['clutch_replacement.md']
print([s.value for s in outcome.states])
```

Swap the proposal for `"rm -rf /"`, a tool name that does not exist, a call
hidden inside `reasoning=`, or a smuggled `"max_attempts": 999` and the run
ends at a normalized, bounded, audited rejection with the executor untouched.

## The filesystem capability

Two tools, both read-only: `workspace.read` and `workspace.list`. The model
sees an abstract namespace of exactly two roots and supplies a relative path:

```json
{"tool": "workspace.read",
 "arguments": {"root_id": "workspace", "path": "src/app.py"}}
```

`workspace` and `knowledge` are labels. The physical directory each maps to is
chosen by trusted wiring, held in one module, and never appears in a result,
an error message, or an audit event.

```python
from local_agent.wiring import (
    build_filesystem_registry,
    build_filesystem_run_context,
    build_physical_roots,
)

roots = build_physical_roots(
    {"workspace": "/srv/agent/workspace", "knowledge": "/srv/agent/knowledge"}
)
registry = build_filesystem_registry(roots)
context = build_filesystem_run_context("run-1")
```

**Containment.** A path is authorized only when, after full symlink
resolution, it is still inside the resolved root:

    resolved_candidate.is_relative_to(resolved_authorized_root)

That is a component-wise comparison, deliberately not a string prefix test —
`"/srv/workspace_evil/loot".startswith("/srv/workspace")` is `True`, and a test
named for that attack asserts both that the naive check would have been fooled
and that the real one is not.

**Symlinks** are resolved first and the physical target is authorized second: a
link staying inside the root is followed, one landing outside is denied before
any read. Listings never follow a link at all — an entry is labelled `symlink`
without its target being stat'ed, so a link pointing outside discloses nothing.

**Ceilings** are policy authority and no argument schema exposes them: 256 KiB
per file (counted in bytes, not characters), 1,000 directory entries, 1,024
path characters, 512 KiB serialized result. Exceeding one is a rejection, never
a silent truncation.

**Read-only** is structural. There is no write, delete, rename, mkdir, or chmod
tool to route a request to; the executor module calls no mutating method and
opens files only in mode `"rb"`; and both facts are asserted against the
module's own AST.

> The filesystem adapter is read-only and does **not** constitute an OS-level
> sandbox. Path containment protects the capability boundary within the
> configured roots. It does not protect against every operating-system or
> filesystem attack — notably TOCTOU races and hard links, both of which
> presuppose an attacker who can already write inside a root. See
> [`docs/milestone-2-decisions.md`](docs/milestone-2-decisions.md) §12.

## Why the model cannot escalate

| Attack | Why it fails |
|---|---|
| Tool call hidden in reasoning | The parser reads one field; the others are never an input |
| Malformed or multiple JSON calls | One envelope, strictly typed, or `TOOL_CALL_MALFORMED` |
| Shell text (`rm -rf /`) | No shell executor exists to route it to — it is only ever a string |
| Unknown tool name | Resolved against a registry with no mutation API; miss is terminal |
| Arbitrary path as `root_id` | `Literal["workspace","knowledge"]` rejects it at the schema |
| Schema-legal but ungranted root | A separate authorization gate reads grants from frozen config |
| Smuggled `max_attempts` | Boundary models forbid extra fields; the budget lives in `RunContext` |
| Infinite retry loop | Bounded at 3 attempts; identical proposals still consume budget |
| Prompt injection in a tool result | Results are data; nothing re-reads them as instructions |
| Corrupt tool result | Verified against the declared result schema; a bad shape is an error, not a crash |
| `../../etc/passwd` as a path | Refused by the schema before any join or filesystem contact |
| `/etc/passwd`, `C:\x`, `\\server\share`, `~/.ssh` | Same — an absolute path would otherwise *replace* the root when joined |
| Symlink pointing outside the root | Resolved first, then denied; no read occurs |
| Sibling directory `workspace_evil` | Containment is `is_relative_to`, not `startswith` |
| Reaching the other root through a symlink | `root_id` selects the root; the path cannot re-select it |
| A file larger than the ceiling | At most ceiling+1 bytes are ever read; the request is denied, not truncated |
| Instructions inside a file's contents | Returned as data; nothing re-reads a result as control input |

Each row has a test, and each rejection test also asserts the executor's call
count is zero.

## Layout

    src/local_agent/
      contracts.py      typed boundary models (frozen, extra="forbid")
      state_machine.py  State enum + explicit transition table
      registry.py       ToolSpec, ToolRegistry, ToolExecutor protocol
      policy.py         RunContext (frozen authority) + the two gates
      controller.py     the orchestrator — the only component with authority
      model_adapter.py  ModelAdapter protocol + deterministic fake
      events.py         structured audit records (no secrets, no wall clock)
      wiring.py         trusted startup assembly
      executors/
        file_search.py  the Milestone 1 deterministic fake
        workspace_fs.py the only module permitted to touch a filesystem

## Scope

**Implemented:** deterministic controller, state machine, model adapter
interface, tool specification, `ControllerError`, `ToolFeedback`, typed result
boundary, authorization, policy, retry budget, parser boundary, fake model
adapter, audit events, a read-only filesystem capability, and the test suite.

**Deliberately absent:** writes of any kind, shell or subprocess execution,
Playwright or any browser, network access, MCP, Docker code execution, Qdrant,
SQLite persistence, Gemma, llama.cpp, and OS-level sandboxing.
`tests/test_architecture.py` enforces this against the package's own AST, with
the filesystem grant scoped to one named module — the absence is checked, not
merely stated.

## Further reading

- [`docs/milestone-1-decisions.md`](docs/milestone-1-decisions.md) — controller conflicts, resolutions, deviations
- [`docs/milestone-2-decisions.md`](docs/milestone-2-decisions.md) — filesystem path model, symlink policy, ceilings, and known limitations
- [`CLAUDE.md`](CLAUDE.md) and [`.claude/rules/`](.claude/rules/) — working rules for this subproject
