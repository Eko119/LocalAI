# Local AI Agent — Milestone 1: Deterministic Controller Foundation

A deterministic control plane that treats an LLM as an untrusted proposal
engine. The model may suggest a tool call; nothing else about the model's
output has any authority.

    MODEL PROPOSES · CONTROLLER DECIDES · POLICY AUTHORIZES
    EXECUTOR ACTS  · VERIFIER CHECKS   · PERSISTENCE RECORDS

This milestone deliberately does **not** build the agent. It proves, with
executable tests, that a model producing arbitrary malformed or hostile output
cannot obtain unauthorized execution authority.

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

## Example

```python
import asyncio, json

from local_agent.contracts import ModelResponse
from local_agent.controller import Controller
from local_agent.model_adapter import ScriptedModelAdapter
from local_agent.policy import RunContext
from local_agent.wiring import build_default_registry

proposal = json.dumps({
    "tool": "file_search",
    "arguments": {"query": "Jeep clutch notes", "root_id": "workspace"},
})

controller = Controller(
    build_default_registry(),
    ScriptedModelAdapter((ModelResponse(structured_output=proposal),)),
)

outcome = asyncio.run(
    controller.run(RunContext(run_id="demo"), [{"role": "user", "content": "find them"}])
)

print(outcome.terminal)   # status='succeeded' attempts=1
print(outcome.result)     # status='success' data=['clutch_replacement.md']
print([s.value for s in outcome.states])
```

Swap the proposal for `"rm -rf /"`, a tool name that does not exist, a call
hidden inside `reasoning=`, or a smuggled `"max_attempts": 999` and the run
ends at a normalized, bounded, audited rejection with the executor untouched.

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
      executors/        Milestone 1 ships one, and it is a fake

## Scope

**Implemented:** deterministic controller, state machine, model adapter
interface, tool specification, `FileSearchArgs`, `ControllerError`,
`ToolFeedback`, typed result boundary, authorization, policy, retry budget,
parser boundary, fake model adapter, `FakeFileSearchExecutor`, audit events,
and the test suite.

**Deliberately absent:** real filesystem access, shell or subprocess execution,
Playwright or any browser, network access, MCP, Docker code execution, Qdrant,
SQLite persistence, Gemma, and llama.cpp. `tests/test_architecture.py` enforces
this against the package's own AST — the absence is checked, not merely stated.

## Further reading

- [`docs/milestone-1-decisions.md`](docs/milestone-1-decisions.md) — conflicts, resolutions, deviations
- [`CLAUDE.md`](CLAUDE.md) and [`.claude/rules/`](.claude/rules/) — working rules for this subproject
