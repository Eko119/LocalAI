# 04 — Implementation Roadmap

## Phase 0 — Repository foundation
- Create canonical source tree.
- Add AGENTS.md.
- Pin Python/runtime versions.
- Configure `uv` lockfile.
- Configure tests and CI.
- Establish structured logging without secrets.

Gate: clean environment reproduces the same dependency graph.

## Phase 1 — Deterministic controller
Implement:
- state enum
- transition table
- run context
- tool registry
- normalized errors
- retry budget
- terminal states

Gate: state-machine tests prove illegal transitions are rejected.

## Phase 2 — FakeFileSearch
Schema:

```python
class FileSearchArgs(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    root_id: Literal["workspace", "knowledge"]
    max_results: int = Field(default=10, ge=1, le=50)
```

Deterministic fixtures:
- `Jeep clutch notes` -> known success payload
- `timeout_trigger` -> simulated timeout
- all other queries -> empty result

Gate: all adversarial tests pass.

## Phase 3 — ModelAdapter
Define a narrow adapter interface. Treat generation as untrusted text/structured candidate data.

Gate: fake model can reproduce valid and adversarial outputs deterministically.

## Phase 4 — Real local inference
Integrate llama.cpp through a controlled adapter.

Gate: exact model/runtime identity recorded and benchmarked.

## Phase 5 — Native file search
Replace the fake executor with a read-only implementation.

Security:
- approved root IDs only
- canonicalized paths
- no arbitrary path access
- no symlink escape
- bounded result count
- bounded file size
- timeout

Gate: fake and real executor satisfy the same ToolSpec.

## Phase 6 — Playwright
Only after file-search acceptance.

Start read-only:
- navigation allowlist
- timeout
- download restrictions
- isolated browser profile
- no secret injection
- page content treated as untrusted

Gate: prompt-injection and navigation-policy tests pass.

## Phase 7 — Controlled write/code tools
Add one capability at a time, each with its own policy and tests.

## Phase 8 — Memory
- SQLite for operational state and metadata.
- Qdrant for semantic retrieval if required.
- Explicit provenance for every memory item.
- Retrieval results remain untrusted data.

## Phase 9 — Production hardening
- reproducible builds
- benchmark regression suite
- security review
- crash recovery
- audit logs
- backup/restore
- resource monitoring
