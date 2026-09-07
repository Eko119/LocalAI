"""Authorization and policy: two separate gates, both controller-owned.

Spec 07/§"authorization_and_policy" is explicit that these are different
concepts:

    schema validity  does not imply  authorization
    authorization    does not imply  policy approval

So they are two distinct states (AUTHORIZE, POLICY_CHECK) backed by two
distinct functions here, evaluated in that order, both before EXECUTE.

* Authorization answers "is this run permitted to touch this tool and this
  named root at all?" — it is about *grants* held by the run.
* Policy answers "given that the run holds the grant, do the operational
  rules allow this specific request right now?" — it is about *rules*
  applied to the concrete arguments.

Both read exclusively from `RunContext`, a frozen object built by trusted
application wiring. No field of it is ever derived from model output, so
there is no code path by which a proposal can widen its own grants.

Externally both gates emit the same `POLICY_DENIED` code. That is
deliberate (spec §"feedback_security"): telling the model *which* gate
rejected it, and why, turns a denial into a bypass tutorial. The precise
internal reason is recorded in the audit event stream instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel

from .registry import ToolSpec

# The only root IDs that exist (spec §"authorization_and_policy"). These are
# abstract labels. The physical directory each one maps to is chosen by
# trusted wiring and never appears in this module.
LEGAL_ROOT_IDS: frozenset[str] = frozenset({"workspace", "knowledge"})


@dataclass(frozen=True)
class FilesystemLimits:
    """Resource ceilings for the read-only filesystem capability.

    These are policy authority, not model input: no tool argument schema
    exposes a byte count, an entry count, or a size. The same frozen object
    is handed to the executor by trusted wiring, so the ceiling enforced
    during a physical read is the ceiling policy declared — there is one
    source of truth rather than two that can drift.

    Ceilings are enforced by rejection, not truncation. A silently truncated
    file or listing is indistinguishable from a complete one, which is a poor
    property for data a model will reason over.
    """

    # Bytes, not characters. UTF-8 text can spend several bytes per character,
    # so a character-based limit would not bound memory or transfer.
    max_file_read_bytes: int = 262_144  # 256 KiB
    # Milestone 8. Deliberately a *separate* field rather than a reuse of the
    # read ceiling, because the two bound different resources and a shared
    # value would let one be raised for one reason and silently widen the
    # other. A read bounds transient memory and how much reaches the model's
    # context; a write bounds durable disk consumption inside a workspace and,
    # because the arguments are persisted, how much lands in a journal record.
    #
    # The value is an order of magnitude below the read ceiling and below
    # `records.MAX_ARGUMENTS_BYTES` (16 KiB), so an ordinary payload is bounded
    # by the capability rather than by the persistence layer. Worst-case JSON
    # escaping (a payload of control characters inflates six-fold) can still
    # exceed the record ceiling; that is a clean, non-retryable refusal rather
    # than a crash — see `Controller._persist_authorization`.
    max_file_write_bytes: int = 8_192  # 8 KiB
    max_directory_entries: int = 1_000
    # May tighten, never widen, the schema's structural MAX_PATH_LENGTH.
    max_path_length: int = 1_024
    # Backstop on the serialized result handed back to the controller.
    max_serialized_result_bytes: int = 524_288  # 512 KiB

    def __post_init__(self) -> None:
        for name in (
            "max_file_read_bytes",
            "max_file_write_bytes",
            "max_directory_entries",
            "max_path_length",
            "max_serialized_result_bytes",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be >= 1")


DEFAULT_FILESYSTEM_LIMITS = FilesystemLimits()


@dataclass(frozen=True)
class RunContext:
    """Trusted, immutable configuration and budget for a single run.

    Frozen because every field here is authority: `max_attempts` is the retry
    budget the model may not change, `authorized_*` are the grants it may not
    widen. A frozen dataclass makes tampering a `FrozenInstanceError` at the
    point of attempt rather than a silent state change.
    """

    run_id: str
    max_attempts: int = 3
    authorized_tools: frozenset[str] = field(default_factory=lambda: frozenset({"file_search"}))
    authorized_roots: frozenset[str] = field(default_factory=lambda: frozenset(LEGAL_ROOT_IDS))
    allow_destructive: bool = False
    # Policy-level ceiling on result count. Distinct from the schema bound:
    # the schema says what is *structurally* sayable (1..50), this says what
    # this particular run is *operationally* allowed to ask for.
    max_results_ceiling: int = 50
    # Resource ceilings for the filesystem capability. Wiring passes this same
    # object to the executors, so policy and physical enforcement agree.
    filesystem: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        illegal = self.authorized_roots - LEGAL_ROOT_IDS
        if illegal:
            raise ValueError(f"authorized_roots contains non-existent roots: {sorted(illegal)}")


@dataclass(frozen=True)
class Decision:
    """Outcome of a gate. `reason` is controller-private; it never reaches the model."""

    allowed: bool
    reason: str = "ok"


def authorize(spec: ToolSpec, args: BaseModel, run: RunContext) -> Decision:
    """AUTHORIZE gate: does this run hold the grants this call requires?"""
    if spec.requires_authorization and spec.name not in run.authorized_tools:
        return Decision(False, "tool_not_granted")

    # General rule, not a file_search special case: any tool whose arguments
    # name a root must name one this run holds a grant for. A future tool
    # with a `root_id` field is covered automatically; a tool without one is
    # simply not root-scoped.
    root_id = getattr(args, "root_id", None)
    if root_id is not None:
        if root_id not in LEGAL_ROOT_IDS:
            # Defence in depth: the schema's Literal should already have
            # rejected this, so reaching here means the schema and the root
            # registry disagree. Deny rather than trust the schema.
            return Decision(False, "root_not_recognised")
        if root_id not in run.authorized_roots:
            return Decision(False, "root_not_granted")

    return Decision(True)


def evaluate_policy(spec: ToolSpec, args: BaseModel, run: RunContext) -> Decision:
    """POLICY_CHECK gate: do operational rules permit this concrete request?

    Runs only after `authorize` has passed, and always before EXECUTE.
    """
    if spec.destructive and not run.allow_destructive:
        return Decision(False, "destructive_not_permitted")

    max_results = getattr(args, "max_results", None)
    if isinstance(max_results, int) and max_results > run.max_results_ceiling:
        return Decision(False, "max_results_above_policy_ceiling")

    # General rule, like the root check in `authorize`: any tool whose
    # arguments carry a `path` is subject to this run's path-length ceiling.
    # The schema already bounds it structurally; this lets a run tighten it.
    path = getattr(args, "path", None)
    if isinstance(path, str) and len(path) > run.filesystem.max_path_length:
        return Decision(False, "path_above_policy_length_ceiling")

    return Decision(True)
