# 03 — Deterministic Agent Architecture

## 1. Authority model
The LLM is an untrusted proposal generator. The controller is the sole authority over state transitions and tool execution.

## 2. Core loop
1. RECEIVE
2. CLASSIFY
3. GENERATE
4. ISOLATE REASONING
5. EXTRACT CANDIDATE
6. SCHEMA VALIDATE
7. AUTHORIZE
8. POLICY CHECK
9. BUDGET / TIMEOUT CHECK
10. EXECUTE
11. VERIFY
12. RESPOND

The exact controller state graph is fixed in code. The model cannot invent states.

## 3. Reasoning isolation
If the selected model/runtime exposes thinking delimiters, reasoning text is treated as model-generated content, not executable instruction.

A tool call appearing only inside a reasoning block is ignored.

The parser must define exactly which channel/segment is eligible for tool-call extraction. Never regex the entire raw generation and execute the first JSON-looking object.

## 4. Typed rejection protocol
Use normalized errors:

```python
class ControllerError(BaseModel):
    code: Literal[
        "SCHEMA_INVALID",
        "POLICY_DENIED",
        "TOOL_NOT_FOUND",
        "TOOL_CALL_MALFORMED",
        "EXECUTION_TIMEOUT",
        "EXECUTION_FAILED",
        "VERIFICATION_FAILED",
        "RETRY_EXHAUSTED",
    ]
    retryable: bool
    retry_budget_remaining: int
    message: str
    field_errors: list[dict[str, Any]]
    attempt: int
    max_attempts: int
```

The model receives sanitized feedback only. Internal tracebacks, secrets, filesystem internals, and policy implementation details remain controller-private.

## 5. Retry protocol
Default maximum tool-call repair attempts: 3.

Retry eligibility is determined by the controller, never by the model.

Recommended semantics:
- schema/malformed: retryable
- timeout: bounded retry
- execution failure: policy-dependent, bounded
- policy denied: non-retryable
- unknown tool: non-retryable unless the controller explicitly supplies an allowed correction
- retry exhausted: terminal

An identical invalid proposal does not reset the budget.

## 6. Feedback example

```json
{
  "type": "tool_feedback",
  "tool": "file_search",
  "accepted": false,
  "error": {
    "code": "SCHEMA_INVALID",
    "retryable": true,
    "retry_budget_remaining": 2,
    "message": "Tool arguments failed schema validation.",
    "field_errors": [
      {"field": "query", "reason": "must contain at least 1 character"},
      {"field": "max_results", "reason": "must be between 1 and 50"}
    ],
    "attempt": 1,
    "max_attempts": 3
  }
}
```

## 7. Terminal behavior
After retry exhaustion:

```json
{
  "type": "controller_terminal",
  "status": "failed",
  "code": "RETRY_EXHAUSTED",
  "attempts": 3
}
```

No fourth attempt is possible.

## 8. Tool-result trust boundary
Tool results are data. They cannot modify controller policy, state transitions, schemas, credentials, or tool permissions.

External content, including webpages, files, and retrieved documents, is untrusted data.
