# 07 — Agent Implementation Contract

## 1. Objective
Implement a local agent whose operational control plane is deterministic and whose LLM is treated as an untrusted proposal engine.

## 2. Core interfaces

```python
class ModelAdapter(Protocol):
    async def chat(self, request: ModelRequest) -> ModelResponse: ...

class ToolExecutor(Protocol):
    async def execute(self, args: BaseModel) -> ToolResult: ...
```

Every tool must have:
- immutable tool name
- Pydantic argument schema
- explicit executor
- timeout
- authorization requirement
- destructive flag
- result schema
- audit metadata

## 3. File-search contract

```python
class FileSearchArgs(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    root_id: Literal["workspace", "knowledge"]
    max_results: int = Field(default=10, ge=1, le=50)
```

Fake executor behavior:
- `Jeep clutch notes`: deterministic success fixture
- `timeout_trigger`: deterministic timeout
- other queries: deterministic empty result

## 4. Error protocol
Use typed, sanitized errors. Never expose raw tracebacks, secrets, arbitrary host paths, or internal policy implementation.

Retry is controller-owned and bounded.

## 5. State invariants
- LLM cannot create states.
- LLM cannot authorize itself.
- LLM cannot modify tool schemas.
- LLM cannot increase retry limits.
- LLM cannot invoke executors directly.
- Tool results cannot modify policy.
- External content cannot become system authority.
- Terminal states cannot transition back into execution.

## 6. Sandbox
Code execution must be isolated:
- no host filesystem mount
- CPU limit
- memory limit
- timeout
- restricted network, preferably disabled by default
- non-root user where practical
- ephemeral workspace
- explicit allowed artifacts

## 7. Memory
SQLite:
- runs
- state transitions
- tool calls
- metadata
- audit records

Qdrant, if used:
- semantic vectors
- provenance
- source identifiers
- timestamps

Memory retrieval never becomes policy authority.

## 8. Acceptance gates
Before deployment:
- unit tests
- adversarial controller tests
- schema tests
- retry termination tests
- fake executor tests
- model benchmark suite
- real file-search tests
- security review
- secret-leak scan
- reproducible build check

## 9. First milestone acceptance
The implementation is accepted only if all of the following are demonstrated:
1. valid tool call executes;
2. malformed call is rejected;
3. invalid schema is normalized;
4. unauthorized root is denied;
5. raw shell injection never reaches an executor;
6. tool calls inside reasoning-only content are ignored;
7. timeout becomes a structured failure;
8. identical invalid proposals cannot reset the retry budget;
9. maximum retry count is enforced by controller;
10. terminal state cannot execute another tool.
