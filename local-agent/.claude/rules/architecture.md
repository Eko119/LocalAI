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
| whether a *write* destination is inside its root | the same helper, on the destination's **parent**, plus `O_NOFOLLOW` on the leaf | a second containment implementation |
| whether a destination's file type is writable | `workspace_write.execute`, before the open | an errno discovered afterwards |
| whether a destination may be *appended to* | `workspace_append.execute`, before the open, with no `O_CREAT` in the flags | a create-if-missing convenience |
| whether an ambiguous execution may be repeated | `ToolSpec.re_executable`, in both the retry gate and `_available_actions` | the disposition, which answers a different question |
| how a run whose effect is unknowable ends | an operator `abort` or `terminalize` — a control-plane transition | any path that reaches an executor |
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
| whether a capability may exist at all | `registry.admit` | construction succeeding |
| what a capability *is* | the immutable `ToolSpec` | anything at runtime |
| whether repeating a capability is safe | `ToolSpec.re_executable` | the error code alone |
| whether anything observable happened | `ToolSpec.side_effect_free` | the same flag as retry |
| a capability's identity over time | `registry.capability_digest` | a name alone |
| which capabilities exist | `wiring` + `ToolRegistry.__init__` | runtime registration |

## Rules

1. **The transition table is the specification.** Add a state or an edge by
   editing `TRANSITIONS` and its tests, never by adding control flow that
   bypasses `Run.advance`.
2. **The registry is assembled at startup and never mutated.** `ToolRegistry`
   has no mutation API, its map is a `MappingProxyType`, and `__setattr__`
   refuses rebinding. Keep all three: before Milestone 7 the map was a plain
   dict and both `_by_name["x"] = spec` and `_by_name = {}` worked.
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
   `executors/workspace_fs.py` holds the only workspace *read* grant,
   `executors/workspace_write.py` the only workspace *write* grant,
   `persistence/journal.py` the only durable-state write grant, and
   `transports/http.py` the only network grant. Reading and writing a
   workspace are deliberately two modules and two grants: the reader's
   read-only proofs are AST assertions, and a writer beside it would have to
   weaken them. To give another module a grant, add it to
   `MODULE_IMPORT_GRANTS` deliberately and say why — never widen
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
19. **Admission is unconditional, and there is no "already checked" marker.**
    `ToolRegistry` runs `admit` on every entry. Never add an `admitted` field
    or any other mark to skip the check — a mark is a field, and
    `dataclasses.replace` copies fields onto a spec whose properties have since
    changed, which is exactly how an unchecked capability would look checked.
20. **A capability declares what it is, never what it is allowed.**
    `requires_authorization` and `destructive` describe the capability;
    `RunContext` decides what this run may do with it. Never let a capability
    carry a grant, a budget, a root, or a per-run ceiling — and never admit a
    `destructive` capability that does not require authorization, because
    `authorize` skips the grant check for it entirely.
21. **Three-valued side effects, two derived properties.** Never collapse
    `SideEffect` into a boolean, never store `side_effect_free` or
    `re_executable`, and never equate either with retryability. The retry
    branch is `error.retryable AND (nothing ran OR re_executable) AND budget`.
22. **A side effect is one named operation, never a seam.** `workspace.write`
    replaces one regular file and does nothing else. A new filesystem
    operation means a new module, a new schema, a new registry entry and new
    tests — never a mode argument, an operation name, or a `writable=True`
    flag. The writable registry and run context are separate *builders* for
    the same reason: a flag is one edit away from being passed by a caller who
    did not think about it.
23. **Reuse containment; adapt at the edge.** `_resolve_within_root` resolves
    strictly and cannot resolve a file that does not exist, so the writer
    resolves the *parent* through it and handles the single remaining
    component with `O_NOFOLLOW`. Never fork the helper, never add a
    non-strict mode to it, and never conclude that the leaf's flag makes the
    parent's resolution optional — it guards only the last component.
24. **Enforcement belongs where it is unraceable.** A pre-flight type check
    that the kernel could invalidate before the syscall is diagnosis. Prefer a
    flag on the syscall itself, and say plainly in the code which of the two a
    given check is — with one exception recorded at its site: the
    non-regular-destination check has no syscall behind it and prevents an
    unbounded block, so it is enforcement.
25. **Four axes, four answers.** `side_effect_free`, `re_executable`, the
    journal's evidence, and the recovery disposition correlated for every
    capability before `workspace.append` existed. They are not the same
    question and must never be substituted for one another because they happen
    to agree. `MUTATING` is the first classification where they come apart, and
    the gates that read them — the controller's retry branch and
    `recovery._available_actions` — must both key on `re_executable`.
26. **Escalation is named, monotonic, and asked for.** Three registry builders
    and three run-context builders: read, read+replace, read+replace+append.
    Never add an `include_mutation=True` flag; the distance between "replaces a
    file" and "cannot be repeated at all" deserves more than a default
    argument.
27. **A capability whose effect cannot be verified still has an exit.** When
    `resume` is withheld, `abort` and `terminalize` remain available, and both
    are pure state transitions. M9 must not create an operational dead end —
    and it must not escape one by inventing a path that executes.
28. **Detect what you cannot prevent.** A capability's schemas are mutable
    classes, so `capability_digest` exists because freezing them is impossible.
    Never describe the digest as a tamper seal, and never treat a missing
    digest as a verified one.
