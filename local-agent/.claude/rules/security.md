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

Filesystem access is granted to exactly one module,
`executors/workspace_fs.py`, via `MODULE_IMPORT_GRANTS`. Never satisfy a
one-module need by widening the global allowlist: that would hand the same
capability to the controller and the policy gates, which must remain unable to
perform the operations they authorize.

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

## Audit

Events record structural facts only: state names, tool names, error codes,
counts, internal reason codes. Never log argument values, model text, or result
contents — an audit stream that quotes an injection payload has re-introduced
it somewhere new.
