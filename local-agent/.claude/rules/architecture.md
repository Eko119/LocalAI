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
| which physical directory a root id means | `wiring.build_physical_roots` | anything the model sent |
| whether a resolved path is inside its root | `workspace_fs._resolve_within_root` | a string prefix test |
| filesystem resource ceilings | `policy.FilesystemLimits` | a tool argument |
| where the model service lives | `model_config.ModelServiceConfig` | model output, ever |
| model timeout and response ceilings | `model_config.ModelServiceConfig` | the model, or a tool argument |
| which response channel may be parsed | `controller.parse_candidate` | the adapter |
| what an execution is | `persistence.records.derive_execution_id` | an id read out of a file |
| whether a crashed run may re-execute | `recovery.plan_recovery` + `ToolSpec.side_effect_free` | the journal's own claim |
| whether repeating a tool is safe | trusted wiring, on the frozen `ToolSpec` | a proposal, a result, or a record |
| which recovery actions exist | `recovery._available_actions` | an operator-supplied string |
| what a recovery plan is | `recovery.plan_recovery` + `derive_plan_id` | a plan the operator submits |
| whether a decision binds | `operator.validate_decision` | the decision's own say-so |
| whether a resumed execution may run | `Controller._revalidate_recovery` | a recorded approval alone |

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
7. **Physical capability is granted per module, never globally.**
   `executors/workspace_fs.py` holds the only filesystem *read* grant,
   `persistence/journal.py` the only durable *write* grant, and
   `transports/http.py` the only network grant. To give another module one, add
   it to `MODULE_IMPORT_GRANTS` deliberately and say why — never widen
   `ALLOWED_IMPORTS`, which would grant it to the controller and the policy
   gates too.
8. **Capabilities are named, not parameterised.** There is no
   `filesystem.operation(name, path)` seam. Adding a dangerous operation must
   require a new class, a new schema, a new registry entry, and new tests —
   never just a new string.
9. **An executor may deny, never grant.** `ToolDenialError` exists because
   containment can only be established after physical resolution. It is
   fail-closed by construction: an executor cannot hand itself authority it
   was not wired with.
10. **The adapter transports; the controller interprets.** A model adapter maps
    wire fields onto the three channels and stops. It must not validate a
    proposal, resolve a tool, decide retryability, or recover a missing
    structured output from narrative — and it must never grow a second parser
    beside `parse_candidate`.
11. **Retry lives in one place.** Neither an adapter nor a transport may retry.
    A transport retrying three times inside a controller retrying three times
    makes nine calls against a budget of three, invisibly.
12. **Persistence records; it never decides.** The journal is a durable
    representation of controller-owned state, not a second source of truth.
    Recovery re-validates every record against the live registry and the live
    `RunContext` and treats disagreement as fatal. Never read a budget, a
    grant, a tool identity, or a state transition *out of* the file, and never
    add a repair path that "fixes" a record to make a run resumable.
13. **Authorize durably, then execute.** The `ExecutionAuthorized` record is
    written and `fsync`'d *before* the executor is called. Reversing that
    ordering would trade a detectable ambiguity for an invisible one: a side
    effect that happened with nothing on disk saying so.
14. **Replay observes; it cannot act.** `recovery.replay` takes no executor and
    must never reach `ToolSpec.executor`. Reconstructing a run is a read of
    records, so an untrusted journal has nothing there to trigger.
15. **The operator picks from the controller's options; they do not supply
    their own.** The controller derives the plan and its `available_actions`;
    an `OperatorDecision` names one. Never accept a plan, a tool, arguments, a
    budget, an execution identity, or an executor *from* an operator — and
    never widen `OperatorDecision`, whose missing fields are the enforcement.
16. **Approve, then re-establish everything.** An approval is a statement about
    a moment. `Controller.recover` persists the decision, then re-reads the
    journal, re-derives the plan, re-resolves the `ToolSpec`, re-validates the
    arguments, re-runs both gates, and re-derives the execution identity before
    an executor is reached. Never shortcut that with "the operator already
    approved it".
17. **Resume re-enters the ordinary path.** `Controller.run` and
    `Controller.recover` share `_loop`; a resume differs only by taking its
    operation from the journal instead of the model. Never add a second
    execution path — a recovery executor would be a second place to forget a
    gate. And never write a second `ExecutionAuthorized`: the write-ahead
    record already on disk is the authorization.
18. **There is no admin mode.** No `--force`, `--unsafe`, `--ignore-policy`,
    `--bypass`, `--superuser`, `--emergency`, or any equivalent flag, kwarg or
    environment variable. If recovery is blocked, the answer is a new run, not
    a bypass.
