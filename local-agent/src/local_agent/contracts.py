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

from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator


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
# Filesystem capability (Milestone 2)
# --------------------------------------------------------------------------

# The complete model-facing namespace. The model names an abstract root; the
# physical directory each one maps to lives only in trusted wiring and inside
# the executor. See `executors/workspace_fs.py`.
RootId = Literal["workspace", "knowledge"]

# Structural ceiling on a model-supplied path. This is the schema's hard
# boundary; `policy.FilesystemLimits.max_path_length` may tighten it further
# for a given run, exactly as `max_results_ceiling` tightens `max_results`.
MAX_PATH_LENGTH = 1024


def _canonical_relative_path(value: str) -> str:
    """Accept only a canonical, relative, POSIX-style path.

    This is the *syntactic* half of the path security model, and it runs
    before anything touches a filesystem. It rejects, by construction:

    * absolute POSIX paths (`/etc/passwd`) — which would otherwise silently
      replace the root when joined, since `Path("/root") / "/etc"` is `/etc`
    * home expansion (`~/secret`) — this code never calls `expanduser`, but
      a leading `~` is rejected rather than treated as a literal directory
    * Windows drive paths (`C:\\x`, `C:/x`) and UNC paths (`\\\\server`) —
      every backslash is refused, and so is a drive-letter prefix
    * every `..` segment, and the non-canonical `.`, empty (`//`), and
      trailing-separator forms that make one file reachable by many strings
    * NUL bytes, which would otherwise fail deep inside the OS layer

    The empty string is permitted and means "the root itself"; the read tool
    additionally requires a non-empty path via its own `min_length`.

    Physical containment is verified separately, after resolution, in the
    executor. Neither layer is sufficient alone: this one cannot see
    symlinks, and that one cannot run before a path has been joined.
    """
    if "\x00" in value:
        raise ValueError("path must not contain a NUL byte")
    if "\\" in value:
        raise ValueError("path must not contain a backslash")
    if value.startswith("/"):
        raise ValueError("path must be relative, not absolute")
    if value.startswith("~"):
        raise ValueError("path must not start with '~'")
    if len(value) >= 2 and value[1] == ":" and value[0].isalpha():
        raise ValueError("path must not be a drive-qualified path")

    if value == "":
        return value

    for segment in value.split("/"):
        if segment == "":
            raise ValueError("path must not contain an empty segment")
        if segment == ".":
            raise ValueError("path must not contain a '.' segment")
        if segment == "..":
            raise ValueError("path must not contain a '..' segment")

    return value


RelativePath = Annotated[str, AfterValidator(_canonical_relative_path)]


class WorkspaceReadArgs(_Strict):
    """Arguments for `workspace.read`.

    Note what is absent: there is no byte count, no encoding, no offset, no
    follow-symlinks flag, and no root path. Resource ceilings are policy
    authority (`policy.FilesystemLimits`), and the physical root is wiring
    authority. The model chooses *what* to read, never *how much* or *where
    from* in physical terms.
    """

    root_id: RootId
    path: RelativePath = Field(min_length=1, max_length=MAX_PATH_LENGTH)


class WorkspaceListArgs(_Strict):
    """Arguments for `workspace.list`.

    `path` defaults to the empty string, which denotes the root directory
    itself. That avoids needing a `.` segment, which the path validator
    rejects to keep one file reachable by exactly one string.
    """

    root_id: RootId
    path: RelativePath = Field(default="", max_length=MAX_PATH_LENGTH)


class WorkspaceReadResult(_Strict):
    """Result schema for `workspace.read`.

    `path` echoes the model's own abstract path and `root_id` its abstract
    root. No physical path, device, inode, owner, permission, or timestamp
    appears anywhere in this shape.
    """

    status: Literal["success", "error"]
    root_id: RootId
    path: str
    content: str
    bytes_read: int


class DirectoryEntry(_Strict):
    """One entry in a directory listing.

    `kind` is determined without following symlinks: an entry that is a
    symlink is reported as such and its target is never stat'ed, so a link
    pointing outside the root discloses nothing about what is out there.
    """

    name: str
    kind: Literal["file", "directory", "symlink", "other"]


class WorkspaceListResult(_Strict):
    """Result schema for `workspace.list`. Entries are name-sorted; see the executor."""

    status: Literal["success", "error"]
    root_id: RootId
    path: str
    entries: list[DirectoryEntry]


# --------------------------------------------------------------------------
# Constrained artifact writer (Milestone 8)
# --------------------------------------------------------------------------

# A structural ceiling on the *characters* a write may carry, which exists only
# so a hostile payload cannot force the executor to encode an enormous string
# before the byte ceiling is applied. The authoritative bound is
# `policy.FilesystemLimits.max_file_write_bytes`, enforced on encoded UTF-8
# bytes inside the executor; this one stands to it exactly as `MAX_PATH_LENGTH`
# stands to `FilesystemLimits.max_path_length`.
#
# Four bytes is the maximum a single character can occupy in UTF-8, so a string
# within this bound can never encode to more than four times the byte ceiling.
MAX_WRITE_CONTENT_CHARS = 4 * 8_192


class WorkspaceWriteArgs(_Strict):
    """Arguments for `workspace.write`.

    Note what is absent, and that the absences are the contract rather than a
    simplification. There is no mode, no append flag, no encoding, no offset,
    no permission, no owner, no "create parents", no follow-symlinks switch,
    and no root path. The capability does exactly one thing — put these bytes
    at this abstract location — so there is no parameter through which it could
    be asked to do a second thing.

    `path` reuses `RelativePath`, the same canonical grammar the read
    capability uses. A second path grammar for writes would be a second place
    for a traversal bug to live; `min_length=1` is the only difference, because
    a write must name a file and the empty path denotes the root directory.
    """

    root_id: RootId
    path: RelativePath = Field(min_length=1, max_length=MAX_PATH_LENGTH)
    # Text, not bytes, and validated as such. The read capability already
    # refuses non-UTF-8 content; accepting arbitrary bytes here would make the
    # pair asymmetric and would need a base64 channel the model could misuse.
    # The empty string is legal: creating or truncating a file to zero bytes is
    # a coherent request, and refusing it would be an arbitrary exception.
    content: str = Field(max_length=MAX_WRITE_CONTENT_CHARS)


class WorkspaceWriteResult(_Strict):
    """Result schema for `workspace.write`.

    Operational facts only. `root_id` and `path` echo the caller's own abstract
    request; `bytes_written` is what was encoded; `created` says whether the
    destination existed beforehand.

    `created` discloses strictly less than the read capability already does —
    whether a file exists inside a root the run holds a grant for — and a
    caller needs it to tell "I made this" from "I replaced this". No physical
    path, device, inode, mode, owner, or timestamp appears anywhere in this
    shape, and none is collected in order to be omitted.
    """

    status: Literal["success", "error"]
    root_id: RootId
    path: str
    bytes_written: int
    created: bool


# --------------------------------------------------------------------------
# Non-re-executable mutation (Milestone 9)
# --------------------------------------------------------------------------

# The same structural relationship `MAX_WRITE_CONTENT_CHARS` has to the write
# ceiling: a bound on *characters* so a hostile payload cannot force a huge
# encode before the byte ceiling is applied. The authoritative bound is
# `policy.FilesystemLimits.max_file_append_bytes`, enforced on encoded UTF-8.
MAX_APPEND_CONTENT_CHARS = 4 * 4_096


class WorkspaceAppendArgs(_Strict):
    """Arguments for `workspace.append` — the first non-re-executable mutation.

    Deliberately the same shape as `WorkspaceWriteArgs`, and deliberately no
    larger. The two capabilities differ in *semantics*, not in what the model
    is allowed to say, so there is no offset, no position, no seek, no mode, no
    "create if missing", no separator, and no encoding. A caller cannot ask
    where the bytes go: `O_APPEND` means the kernel decides, at end of file.

    The absence of a `create` flag is the contract, not an oversight. The
    executor opens without `O_CREAT`, so a missing destination is refused by
    the syscall rather than by a check someone could later relax.
    """

    root_id: RootId
    path: RelativePath = Field(min_length=1, max_length=MAX_PATH_LENGTH)
    # Text, matching the read and write capabilities. The empty string is
    # legal and is a well-defined no-op append: it is still a real execution
    # with a real identity, and pretending otherwise would introduce a
    # capability-specific special case into an otherwise uniform pipeline.
    content: str = Field(max_length=MAX_APPEND_CONTENT_CHARS)


class WorkspaceAppendResult(_Strict):
    """Result schema for `workspace.append`.

    `bytes_appended` is what the syscall reported writing, not what the caller
    asked to write. The difference matters for exactly one case: a short write
    leaves a partial effect, and reporting the requested count there would be
    the controller stating something the filesystem never confirmed.

    Note what is absent relative to `WorkspaceWriteResult`: there is no
    `created` field, because this capability cannot create. And there is no
    resulting file size, because reporting one would turn every append into a
    read of surrounding content the request never asked for.
    """

    status: Literal["success", "error"]
    root_id: RootId
    path: str
    bytes_appended: int


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


# The reserved name that means "no further execution is required". It is a
# *name*, not a tag, for one measured reason: `LocalAIModelAdapter` builds its
# structured output from `message.tool_calls`, and every path through it emits
# either `{"tool": ..., "arguments": ...}`, a raw malformed-JSON string, or
# `None`. There is no path by which a well-formed generation can carry a
# top-level `type` key, so a tag-shaped completion would have been reachable
# from the test adapter and unreachable from the production one — a contract
# that works only in tests. Measured, not assumed.
#
# Nothing may be *called* this: `registry.admit` refuses it, so the name can
# never resolve to a capability and can never reach an executor.
COMPLETION_TOOL = "execution.complete"


class ExecutionComplete(_Strict):
    """The model's affirmative statement that no further execution is required.

    Milestone 10. This is the *second* shape the structured channel may carry,
    and it exists because the contract previously had no way to say "done".
    Absence of a proposal meant `TOOL_CALL_MALFORMED` — by design, by three
    docstrings in `model_service.py`, and by a named test — so completion had
    to be stated rather than inferred. Making silence mean success would have
    turned a truncated response or a suppressed tool-call channel into a
    successfully completed run, inverting the fail-closed discipline every
    earlier milestone established.

    **Why this cannot be confused with a proposal.** The name is reserved and
    inadmissible, so no capability bears it and the parser routes it here
    before a `RawToolCall` is ever constructed. `arguments` must be empty:
    completion carries no payload, and a completion with arguments is a
    malformed completion rather than a proposal in disguise.
    """

    tool: Literal["execution.complete"]
    arguments: dict[str, Any] = Field(default_factory=dict)

    @field_validator("arguments")
    @classmethod
    def _no_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Strict rather than tolerant: silently ignoring a payload here would
        # give the model a channel the controller does not read, and every
        # other boundary in this package refuses those rather than dropping
        # them.
        if value:
            raise ValueError("execution.complete takes no arguments")
        return value


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
