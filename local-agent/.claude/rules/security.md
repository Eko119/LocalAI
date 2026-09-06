# Security Rules

## Trust boundaries

Three kinds of data cross into this system, and all three are untrusted:

1. **Model output.** Reasoning, narrative, and the structured channel alike.
   Only the structured channel is even read, and only into a typed envelope.
2. **Tool results.** Data, never instruction. A result saying
   `IGNORE CONTROLLER RULES` is a string in a list; nothing re-reads it as
   control input. Never add code that inspects result content for directives.
3. **File contents.** Everything `workspace.read` returns is untrusted data,
   including a file that contains a well-formed tool call. The controller's
   only candidate source is the model's approved channel; nothing re-parses a
   result. Same rule for anything a later milestone retrieves — pages,
   documents, embeddings — with no exception for a source that "looks
   internal".

## What must never leave the controller

Feedback sent to the model must never carry:

- raw tracebacks or upstream exception text
- secrets, tokens, environment variables
- host paths
- which gate rejected a request, or why

Schema errors are the deliberate exception: they state the violated constraint
(`must have at most 500 characters`) because a legitimate repair needs it. They
still never echo the model's own payload back.

A policy denial is a flat `POLICY_DENIED` with an empty `field_errors`. It must
not become a puzzle that teaches the model how to satisfy the gate next time.
Authorization failures and policy failures deliberately share one external code
so the model cannot tell the gates apart.

## Authority is frozen

`RunContext` is a frozen dataclass and every boundary model is a frozen
Pydantic model with `extra="forbid"`. Both properties are load-bearing:

- frozen means a tampering attempt raises at the point of attempt
- `extra="forbid"` means a smuggled `max_attempts` field is a schema violation,
  not a silently ignored key

Do not relax either. Do not add a setter, a `model_config` override, or an
`update()` helper to anything in `contracts.py` or `policy.py`.

## Capabilities

The reason hostile text cannot run a shell command is not that it is filtered —
it is that no shell executor exists to route it to. Keep it that way. The
forbidden-import allowlist in `tests/test_architecture.py` is the enforcement;
widening it requires opening the corresponding milestone first.

Filesystem access is granted per module via `MODULE_IMPORT_GRANTS`:
`executors/workspace_fs.py` may read a workspace, and
`persistence/journal.py` may write the journal — neither can do the other's
job. Never satisfy a one-module need by widening the global allowlist: that
would hand the same capability to the controller and the policy gates, which
must remain unable to perform the operations they authorize.

## The filesystem boundary

- **Containment is `Path.is_relative_to`, never `startswith`.** A sibling
  directory whose name merely begins with the root's name passes a prefix test
  and fails a component test. There is a test named for that attack; if you
  find yourself writing a prefix comparison, that test is the reason not to.
- **Resolve first, then authorize.** Both the root and the candidate are
  fully resolved before comparison. Do not authorize an unresolved path, and
  do not skip resolving the root — a root reached through a symlink makes
  every legitimate child look like an escape.
- **Physical paths are secret.** They must not appear in a result, a
  `ControllerError`, an audit event, or an exception message that reaches the
  model. Native `OSError` text routinely contains them, which is why every
  filesystem failure is translated to a slug at the point it is caught. On
  CPython 3.11 a symlink loop raises `RuntimeError`, not `OSError`, with the
  host path in the message — catch both.
- **Read-only is structural.** No mutating method is called anywhere in the
  executor and `open` is only ever passed `"rb"`; both are asserted against
  the module's AST. Do not add a generic operation seam.
- **Ceilings reject, never truncate.** A shortened file or listing cannot be
  distinguished from a complete one by whoever reads it next.

## The model boundary

- **Only the structured-generation channel is eligible.** LocalAI's
  `message.tool_calls` becomes `structured_output`; `message.reasoning` and
  `message.content` are carried but never parsed. Never add a fallback that
  recovers a proposal from narrative when the tool-call channel is missing —
  fail closed instead.
- **Credentials never cross the transport seam.** `TransportRequest` carries a
  path and a body. The API key lives inside the transport, which injects the
  header itself, which is why a scripted transport can record every request
  verbatim and a test can assert no secret appears.
- **The API key is `repr=False`.** A dataclass repr would print it into any log
  line that rendered the config. Keep it that way, and keep the sentinel test.
- **Transport failures are translated at the point of catch.** `URLError` and
  `HTTPError` messages routinely carry the host and upstream detail; never
  forward one. Emit a stable slug for the audit stream instead.
- **The retry budget is not transmitted.** The adapter projects `ToolFeedback`
  onto `{type, tool, accepted, error:{code, message, field_errors}}`. Adding
  `attempt` or `max_attempts` back to the wire is a regression.
- **URLs are validated at construction**, restricted to `http`/`https`, and may
  not embed credentials. This is a client for one configured model service, not
  a general fetcher.

## The persistence boundary

- **The journal is a record, not an authority.** Recovery re-validates every
  record against the live registry and the live `RunContext`: the run id, the
  budget, the tool's existence, its argument schema, the re-derived execution
  id, and `side_effect_free`. A disagreement is a fatal `RecoveryError`. Never
  add a path that repairs a record, and never take a decision *from* a file.
- **Identity is derived, never carried.** An execution id is
  `sha256(run_id, step_id, attempt, tool, canonical arguments)`. A record whose
  stored id does not re-derive from its own contents is rejected, so an
  attacker cannot rename an execution into one that looks already-completed.
- **The checksum detects corruption, not tampering.** There is no key to
  authenticate with, so it must never be treated as a signature. The
  adversarial tests deliberately recompute it after every mutation; what
  actually defends the system is re-derivation against invariants the file
  cannot influence. Do not describe the checksum as tamper protection.
- **Fail closed on ambiguity.** A crash between authorization and completion is
  `execution_unknown` for any tool not declared `side_effect_free`, and
  `requires_operator` is True. Never resolve an unknown by assuming the
  friendlier branch, and never default `side_effect_free` to True.
- **Write the authorization before executing.** Durability must precede the
  side effect, or a crash leaves an effect with no record of it at all.
- **Replay must not be able to act.** `recovery.replay` takes no executor and
  never reaches `ToolSpec.executor`. Keep it that way — reconstructing a run
  from an untrusted journal must have nothing to trigger.
- **Never persist:** credentials or headers, model reasoning, narrative, raw
  prompts or responses, tool result payloads, physical filesystem paths, or
  exception text. A completion carries a status and a stable reason slug. A
  durable file outlives the process that wrote it, so a secret written there is
  a secret leaked for as long as the file exists.
- **Run ids are filenames.** They are constrained to
  `^[A-Za-z0-9._-]{1,128}$` at the record boundary, which is what stops a run
  id from becoming a path traversal. Do not loosen that pattern.

## The capability boundary

- **Constructing a `ToolSpec` proves nothing; admission does.** A dataclass
  does not validate, so `ToolRegistry` runs `admit` on every entry, every time.
  Never add an "already checked" marker — `dataclasses.replace` copies fields,
  so a mark would survive onto a spec whose properties had changed.
- **A capability declares what it is, never what it is allowed.** The one
  combination where that leaked — `destructive=True` with
  `requires_authorization=False`, which makes `authorize` skip the grant check
  entirely — is now inadmissible. The fix is at admission; `authorize` is a
  Milestone 1 invariant and stays untouched.
- **Names are audit keys and journal values.** Bounded at 64 characters,
  dotted lower-snake only. A path-shaped or whitespace-bearing name is refused.
- **Three-valued side effects.** `NONE` / `IDEMPOTENT` / `MUTATING`, default
  `MUTATING`. `side_effect_free` answers "did anything happen"; `re_executable`
  answers "is repeating safe". Both are derived, so they cannot drift, and they
  are not the same question — never collapse them, and never equate either with
  an error code's retryability.
- **Retry is gated by the capability, not only by the error.** The branch is
  `error.retryable AND (nothing ran OR re_executable) AND budget`. A rejection
  before EXECUTE leaves the ordinary repair loop untouched.
- **What the model is told does not include the classification.** A withheld
  retry still reports `RETRY_EXHAUSTED`; the true reason is a `retry_withheld`
  audit event. Never widen the model-facing code to explain a capability.
- **The registry is immutable in every direction available to ordinary code.**
  `MappingProxyType` for the map, `__setattr__` and `__delattr__` refusing,
  read-only views, duplicates refused rather than replaced. The honest limit:
  `object.__setattr__` defeats this, as it defeats any in-process guard — say
  that rather than claiming immunity.
- **Schemas are classes, and classes are mutable.** So a capability is
  content-addressed: `capability_digest` covers both JSON schemas and the
  declared properties, and recovery fails closed on a mismatch. It detects
  drift, not tampering — there is no key. A record with no digest is
  `capability_verified = False`, never "assumed fine".
- **An executor acts and never decides.** It reaches no `RunContext`, no gate,
  no registry, no journal, no model — asserted against module ASTs *and*
  behaviourally from inside a real `execute`. It may deny via
  `ToolDenialError`; it can never grant.
- **Enforcing a ceiling is not deciding one.** `workspace_fs.py` may import
  `FilesystemLimits`; it may not reach `RunContext`, `authorize`,
  `evaluate_policy` or `Decision`. Keep the ban on the deciding names rather
  than widening it to the module.

## The operator boundary

- **An operator is a trusted actor and an untrusted source of values.** Both
  halves hold at once. Every field of an `OperatorDecision` is checked against
  something the controller derived from the journal moments earlier; the
  decision's only job is to *match*.
- **The prohibitions are schema-level, not check-level.** `OperatorDecision`
  has no `tool`, no `arguments`, no `max_attempts`, no `root_id`, no
  `side_effect_free`, and no executor selector, and `extra="forbid"` makes
  adding one a violation. Never widen it — the missing fields are the
  enforcement, and a validation rule would be weaker.
- **A plan is content-addressed, and recording a decision changes its id.**
  That is what makes staleness structural: an approval cannot be replayed
  against the plan that produced it, a later plan, or another run. Never add a
  code path that carries an approval forward to a regenerated plan.
- **Re-validate after the decision is durable and before any executor.** The
  registry, the argument schema, both gates and the execution identity are all
  re-established. "The operator already approved it" is not a reason to skip
  any of them.
- **`execution_unknown` is never resumable, and that is deliberate.** Offering
  it would let a human assert a fact the controller cannot verify. The cost —
  an operator who knows the effect did not happen must start a new run — is the
  accepted price.
- **Abort is not a tool failure.** No synthesised `ToolExecutionError`, no
  completion record, no fabricated result, no model turn. And it never rewrites
  ambiguity: an authorization with no completion stays on disk exactly as it
  was, beside the abort.
- **A terminal run is final in every status.** `succeeded`, `failed` and
  `aborted` alike offer no actions. Never add a resurrection path.
- **The reason code is a slug, not prose.** `^[a-z][a-z0-9_]{0,63}$` cannot
  spell an instruction, a JSON payload, or a path, which is why the operator
  gets a code rather than a free-text field. Do not loosen it into a message.
- **There is no operator identity, and none is claimed.** The project has no
  authentication model, so no `operator` field is persisted: an
  unauthenticated name would record a claim while implying a verified fact.
  The interface is a trusted local control surface — say that, do not imply
  more.
- **No admin mode, ever.** No `--force`, `--unsafe`, `--bypass`, or any
  equivalent. A generic override would undo every property above at once.

## Audit

Events record structural facts only: state names, tool names, error codes,
counts, internal reason codes. Never log argument values, model text, or result
contents — an audit stream that quotes an injection payload has re-introduced
it somewhere new.
