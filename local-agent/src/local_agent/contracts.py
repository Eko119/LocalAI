"""Typed contracts for the controller/model boundary.

Everything in this module is a boundary type: it either crosses from the
untrusted model into the controller (RawToolCall, ModelResponse) or from the
controller back out to the model (ToolFeedback, ControllerError). All models
use `extra="forbid"` so a model cannot smuggle additional fields (e.g. an
attempted `max_attempts` override) through a schema and have them silently
accepted — an unexpected field is a schema violation, not a bypass.

Nothing in this module is mutable authority. Retry budgets, authorization,
and policy live in `policy.RunContext`, which the model never constructs and
never sees.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    """Base class: reject unknown fields everywhere on this boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------
# Tool argument schemas
# --------------------------------------------------------------------------


class FileSearchArgs(_Strict):
    """Argument schema for the `file_search` tool (spec 07 §3)."""

    query: str = Field(min_length=1, max_length=500)
    root_id: Literal["workspace", "knowledge"]
    max_results: int = Field(default=10, ge=1, le=50)


class FileSearchResult(_Strict):
    """Result schema the fake (and later real) file-search executor must satisfy.

    The executor boundary returns plain dict/JSON-shaped data (see
    `ToolExecutor`); the controller validates it against this schema in the
    VERIFY state. A result that does not match — wrong types, missing keys,
    an unexpected `status` value — is a VERIFICATION_FAILED, not a crash.
    """

    status: Literal["success", "error"]
    data: list[str]


# --------------------------------------------------------------------------
# Model <-> controller channel
# --------------------------------------------------------------------------


class RawToolCall(_Strict):
    """A structured tool-call candidate, already isolated to the approved channel.

    This is the *only* shape the parser ever produces from model output. It
    carries untyped `arguments` because the specific tool's schema (e.g.
    `FileSearchArgs`) is only known once the tool name is resolved against the
    controller-owned registry — see `controller.py`'s VALIDATE state.
    """

    tool: str
    arguments: dict[str, Any]


class ModelRequest(_Strict):
    """What the controller sends to a `ModelAdapter` for one generation step."""

    run_id: str
    step_id: str
    attempt: int
    messages: tuple[dict[str, str], ...]
    feedback: ToolFeedback | None = None


class ModelResponse(_Strict):
    """One generation from the model.

    `reasoning` and `narrative` are untrusted free text. The parser
    (`controller.parse_candidate`) MUST NOT scan them for JSON or tool-call
    shapes — a tool call appearing only in these fields is invisible to the
    controller by construction, not by a text filter. `structured_output` is
    the sole eligible channel: the raw text of whatever structured-generation
    facility the runtime exposes (e.g. a function-calling channel). It may be
    None, empty, or malformed JSON; the parser is responsible for turning it
    into a `RawToolCall` or a normalized `TOOL_CALL_MALFORMED` error.
    """

    reasoning: str | None = None
    narrative: str | None = None
    structured_output: str | None = None


# --------------------------------------------------------------------------
# Normalized error / feedback protocol
# --------------------------------------------------------------------------

ErrorCode = Literal[
    "SCHEMA_INVALID",
    "POLICY_DENIED",
    "TOOL_NOT_FOUND",
    "TOOL_CALL_MALFORMED",
    "EXECUTION_TIMEOUT",
    "EXECUTION_FAILED",
    "VERIFICATION_FAILED",
    "RETRY_EXHAUSTED",
]

# Codes the controller will offer another attempt for, given budget remains.
# This is the single source of truth for retry eligibility — nothing else in
# the codebase (least of all the model) may decide retryability. See
# spec 03-agent-architecture.md §5 and 08-EXACT-DIFFS.md Correction 6.
RETRYABLE_CODES: frozenset[ErrorCode] = frozenset(
    {
        "SCHEMA_INVALID",
        "TOOL_CALL_MALFORMED",
        "EXECUTION_TIMEOUT",
        "EXECUTION_FAILED",
        "VERIFICATION_FAILED",
    }
)


class ControllerError(_Strict):
    """Sanitized, normalized rejection. Never carries a raw traceback or secret."""

    code: ErrorCode
    retryable: bool
    retry_budget_remaining: int
    message: str
    field_errors: list[dict[str, object]] = Field(default_factory=list)
    attempt: int
    max_attempts: int


class ToolFeedback(_Strict):
    """Sanitized feedback sent back to the model after a rejected proposal."""

    type: Literal["tool_feedback"] = "tool_feedback"
    tool: str
    accepted: bool
    error: ControllerError | None = None


class ControllerTerminal(_Strict):
    """Final message when a run ends without a fourth attempt being possible."""

    type: Literal["controller_terminal"] = "controller_terminal"
    status: Literal["succeeded", "failed"]
    code: ErrorCode | None = None
    attempts: int


ModelRequest.model_rebuild()
