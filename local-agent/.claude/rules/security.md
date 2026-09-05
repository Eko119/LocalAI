# Security Rules

## Trust boundaries

Three kinds of data cross into this system, and all three are untrusted:

1. **Model output.** Reasoning, narrative, and the structured channel alike.
   Only the structured channel is even read, and only into a typed envelope.
2. **Tool results.** Data, never instruction. A result saying
   `IGNORE CONTROLLER RULES` is a string in a list; nothing re-reads it as
   control input. Never add code that inspects result content for directives.
3. **Anything a later milestone retrieves** — files, pages, documents. Same
   rule, no exceptions granted on the grounds that a source "looks internal".

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

## Audit

Events record structural facts only: state names, tool names, error codes,
counts, internal reason codes. Never log argument values, model text, or result
contents — an audit stream that quotes an injection payload has re-introduced
it somewhere new.
