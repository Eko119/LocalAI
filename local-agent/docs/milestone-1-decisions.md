# Milestone 1 — Decisions, Conflicts, and Deviations

This records the judgement calls made while implementing the deterministic
controller foundation, so a reviewer can audit the reasoning rather than
reverse-engineer it from the diff.

## 1. Specification conflict: the executor signature

**The conflict.** `07-AGENT-IMPLEMENTATION-CONTRACT.md` §2 declares:

```python
class ToolExecutor(Protocol):
    async def execute(self, args: BaseModel) -> ToolResult: ...
```

The milestone task's mandated `FakeFileSearchExecutor` is synchronous and
returns a plain `dict`:

```python
class FakeFileSearchExecutor:
    def execute(self, args: FileSearchArgs) -> dict: ...
```

These cannot both be satisfied literally.

**Resolution.** `ToolExecutor` is synchronous and returns `dict[str, Any]`.
The mandated executor body is reproduced verbatim, because it is the more
specific and more directly given directive, and because the milestone forbids
every source of real I/O — there is nothing for `async` to yield to. The typed
result boundary the contract wanted is preserved at a different seam: rather
than trusting a `ToolResult` return type, the controller validates the returned
dict against the tool's declared `result_schema` in the VERIFY state. That is
strictly stronger, since an executor cannot lie about its return type.

`ModelAdapter.chat` remains `async` exactly as specified — nothing conflicts
with it, and it is the interface a real runtime will need.

**Consequence for later milestones.** When a real executor needs to block on
I/O, `ToolExecutor` becomes async and `Controller._execute` awaits it. The
change is one method and its call site; no gate moves.

## 2. Python version

`01-platform-and-install.md` recommends "Python 3.12+ only if supported by the
pinned dependency set". The available interpreter is CPython 3.11.15, and the
environment-safety rule says to prefer the existing environment over replacing
a runtime. Nothing in this milestone needs 3.12. `requires-python` is `>=3.11`.

## 3. The parser boundary is a channel, not a filter

The reasoning-isolation requirement could be met by stripping `<|think|>`
regions and parsing what remains. It is not implemented that way.

`ModelResponse` has three fields. `parse_candidate` reads exactly one,
`structured_output`, and never references the other two. A tool call that
exists only inside `reasoning` is not filtered out — it is never an input to
the parser at all. This matters because text filters are defeated by encoding
tricks and delimiter confusion, whereas "that field is not read" has no
bypass. It also directly implements 08 Correction 4: define the eligible
channel, do not regex the whole generation.

## 4. Authorization and policy: two gates, one external code

The specification insists these are separate concepts, but the
`ControllerError` code list has no authorization-specific member. So:

- They are two distinct states (`AUTHORIZE`, `POLICY_CHECK`), two distinct
  functions (`authorize`, `evaluate_policy`), evaluated in that order.
- Both emit `POLICY_DENIED` externally.
- The precise internal reason (`root_not_granted`, `tool_not_granted`,
  `max_results_above_policy_ceiling`, …) goes to the audit event stream only.

Collapsing the external code is not a loss of fidelity — it is the
feedback-security requirement. Telling a model which of two gates stopped it,
and why, is how a denial becomes a bypass tutorial.

**Making the distinction real.** `root_id` is a `Literal["workspace",
"knowledge"]`, so the schema already rejects an arbitrary path. If
authorization only re-checked that, it would be decorative. Instead
`RunContext` carries `authorized_roots` and `authorized_tools` — grants held by
*this run* — so a schema-legal `workspace` request is still denied when the run
only holds the `knowledge` grant. Policy is then a third, independent axis:
`max_results_ceiling` caps what a run may ask for below what the schema permits.
`test_authorize_and_policy_are_independent_functions` demonstrates all four
combinations.

## 5. `EXECUTE -> FEEDBACK` is a legal transition

The core loop runs EXECUTE then VERIFY. But an executor that *raised* produced
no result, and there is nothing for VERIFY to check. Rather than fabricate a
synthetic result to keep the edge count down, the table permits
`EXECUTE -> FEEDBACK` for that case only; a completed execution always passes
through VERIFY. The comment in `state_machine.py` records this.

## 6. `extra="forbid"` on every boundary model

Not in the specification's literal snippets; added deliberately. With
Pydantic's default (`extra="ignore"`), a model could emit

```json
{"tool": "file_search", "arguments": {...}, "max_attempts": 999}
```

and the extra key would be silently dropped. It would not have worked — the
budget is read from `RunContext`, never from the envelope — but it would have
been *ignored* rather than *rejected*, and a silent drop is a bad property in a
security boundary. With `extra="forbid"` the tamper attempt is a first-class
`TOOL_CALL_MALFORMED`, visible in the audit stream.

## 7. Timeouts are declared and normalized, not wall-clock enforced

`ToolSpec.timeout_seconds` exists as the contract requires, is recorded in the
`execution_started` event, and the `TimeoutError` path is fully exercised via
the `timeout_trigger` fixture. What is *not* implemented is a wall-clock
watchdog around the executor call, for two reasons: nothing in Milestone 1 can
block (there is no I/O), and a real timer would introduce the ambient
nondeterminism that `test_determinism.py` exists to exclude. Enforcement lands
with the first executor that can actually block.

## 8. Audit events carry no timestamps

Ordering comes from a monotonic sequence number. A wall-clock field would make
two otherwise identical runs produce different traces, which would make the
deterministic-replay guarantee unprovable. Real-time correlation is a
persistence concern, and persistence is deferred.

## 9. Retry semantics

Controller-owned, from `contracts.RETRYABLE_CODES`:

| Code | Retryable | Rationale |
|---|---|---|
| `SCHEMA_INVALID` | yes | an honest mistake the model can repair |
| `TOOL_CALL_MALFORMED` | yes | same |
| `EXECUTION_TIMEOUT` | yes | bounded transient failure |
| `EXECUTION_FAILED` | yes | bounded, per 03 §5 "policy-dependent, bounded" |
| `VERIFICATION_FAILED` | yes | "selected verification failures" |
| `POLICY_DENIED` | no | retrying a denial is asking twice |
| `TOOL_NOT_FOUND` | no | 03 §5, absent an explicit allowed correction |
| `RETRY_EXHAUSTED` | no | terminal by definition |

There is no de-duplication of proposals: an identical invalid call consumes an
attempt exactly like a novel one, which is what makes the loop provably finite.

## 10. Where this lives in the repository

`local-agent/` is a self-contained Python subproject inside the LocalAI
repository. It shares no code, build, or dependency with LocalAI's Go tree, and
nothing outside `local-agent/` was modified.

The Claude Code guardrail artifacts (`CLAUDE.md`, `.claude/settings.json`,
`.claude/rules/`, `.claude/hooks/`) are scoped to this directory rather than the
repository root, deliberately: a root-level `.claude/settings.json` would impose
this milestone's permission model on the unrelated LocalAI project. They take
effect when `local-agent/` is the working root. Promote them to the repository
root only if the agent project becomes the repository's primary concern.

**On what these artifacts actually guarantee.** `CLAUDE.md` and the rules files
are context, not enforcement — they inform an assistant, they do not constrain
one. The hook is enforcement, but only while a session loads it. The layers
that hold unconditionally are the frozen types, the transition table, the
AST-level architecture tests, the pinned dependency set, and review. This is a
drift-*resistant* arrangement, not a drift-proof one: no amount of prompting
survives a model update, an instruction conflict, or a new tool capability on
its own. Independent layers mean one failure does not become an operational
failure.
