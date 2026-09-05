# Architecture Rules

## The authority pipeline

Nothing executes until every stage has passed, in this order:

    RAW MODEL OUTPUT
      -> PARSE            only the approved structured channel is read
      -> CANDIDATE        a RawToolCall envelope, nothing more
      -> SCHEMA VALIDATE  the tool's own Pydantic schema
      -> AUTHORIZE        does this run hold the grants?
      -> POLICY           do the operational rules allow this request?
      -> BUDGET           is an attempt left?
      -> EXECUTE          the controller calls the executor, never the model
      -> VERIFY           the result is typed before anyone reads it
      -> RESPOND

Each stage is a state in `state_machine.State` and a method on `Controller`.
Skipping one is not a style question: `Run.advance` consults the transition
table, so a code path that tried to jump from PARSE to EXECUTE would raise
`IllegalStateTransitionError` rather than execute.

## Where each decision lives

| Decision | Owner | Never |
|---|---|---|
| what state comes next | `state_machine.TRANSITIONS` | model output |
| which tools exist | `wiring.build_default_registry` | runtime registration |
| whether arguments are valid | the tool's `args_schema` | ad-hoc string checks |
| whether a run holds a grant | `policy.authorize` + `RunContext` | anything the model sent |
| whether a request is permitted | `policy.evaluate_policy` | the tool result |
| how many attempts remain | `RunContext.max_attempts` | the proposal, ever |
| whether an error is retryable | `contracts.RETRYABLE_CODES` | per-call judgement |

## Rules

1. **The transition table is the specification.** Add a state or an edge by
   editing `TRANSITIONS` and its tests, never by adding control flow that
   bypasses `Run.advance`.
2. **The registry is assembled at startup and never mutated.** `ToolRegistry`
   has no mutation API; keep it that way.
3. **The parser reads one field.** `parse_candidate` looks at
   `ModelResponse.structured_output` and nothing else. Never scan `reasoning`
   or `narrative` — not even to filter them. Invisibility beats filtering.
4. **The controller stays model-agnostic.** No vendor SDK, no runtime name, no
   URL in `src/`. A real model arrives as a new `ModelAdapter` implementation.
5. **Solve the general contract.** No branch may key on a test input. If a case
   needs handling, express it as a schema constraint, a policy rule, or a
   registry fact.
6. **Executors are replaceable.** A real implementation must satisfy the same
   `ToolSpec` — same argument schema, same result schema — so swapping it is a
   wiring change, not a controller change.
