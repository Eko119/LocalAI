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

# The only root IDs that exist in Milestone 1 (spec §"authorization_and_policy").
LEGAL_ROOT_IDS: frozenset[str] = frozenset({"workspace", "knowledge"})


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

    return Decision(True)
