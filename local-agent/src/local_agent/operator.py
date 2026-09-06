"""The operator control plane (Milestone 6).

An operator is a trusted actor in the *product* model and an untrusted source
of *values* in the code. Both halves matter:

* trusted, because a human is permitted to decide what happens to a crashed
  run — the controller cannot know whether an ambiguous side effect occurred,
  and refusing to let anyone say so would leave every such run stranded;
* untrusted, because every field an operator sends arrives as data and is
  validated against controller-derived facts before it means anything.

What an operator may say is deliberately narrow: *"I approve this exact
controller-generated plan."* What they may not say is *"execute this."* The
difference is enforced structurally rather than by policy — an
`OperatorDecision` has no field for a tool, no field for arguments, no field
for a budget, and no field for an execution identity it gets to choose. The
only execution identity it carries is one it must *match*, not one it may set.

This module contains no execution path at all. It validates and describes; the
controller acts. It imports neither `controller` nor any model, adapter, or
transport module, so there is nothing here for a hostile decision to reach.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .persistence.records import (
    MAX_OPERATOR_DECISIONS_PER_RUN,
    REASON_CODE_PATTERN,
    RUN_ID_PATTERN,
    SCHEMA_VERSION,
    DurableRecord,
    OperatorAction,
    canonical_json,
)
from .policy import RunContext
from .recovery import Disposition, RecoveryPlan, plan_recovery, replay
from .registry import ToolRegistry


class OperatorDecisionRejected(Exception):
    """A decision was not accepted. Always fatal to that decision; never repaired.

    `reason` is a stable slug, as everywhere else in this codebase. It is safe
    to show an operator — it says which binding failed — and it never reaches
    the model, because nothing in the recovery path talks to one.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class _Strict(BaseModel):
    """Frozen and closed, like every other boundary type in this package."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class OperatorDecision(_Strict):
    """One explicit operator decision about one controller-generated plan.

    Look at what this type *cannot* express. There is no `tool`, no
    `arguments`, no `max_attempts`, no `root_id`, no `side_effect_free`, no
    `authorized_tools`, and no executor selector. `extra="forbid"` means adding
    one in transit is a schema violation rather than an ignored key. So the
    threat-model prohibitions — "operator may not select a replacement tool",
    "may not replace canonical arguments", "may not increase the retry budget"
    — are not rules this module checks; they are sentences the schema has no
    vocabulary for.

    The three identity fields are all *bindings*, checked against values the
    controller derived for itself:

    * `plan_id` binds the decision to one exact plan, and because a plan's id
      covers the number of decisions already recorded, it also binds it to one
      exact moment in that run's history;
    * `expected_execution_id` binds it to the execution the plan concerned;
    * `decision_sequence` binds it to one position in the decision order, so a
      single approval can authorize at most one resume attempt.
    """

    schema_version: int = SCHEMA_VERSION
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    plan_id: str = Field(min_length=32, max_length=32)
    action: OperatorAction
    decision_sequence: int = Field(ge=1, le=MAX_OPERATOR_DECISIONS_PER_RUN)
    # A slug, not prose. The charset forbids spaces, punctuation and uppercase,
    # so this field structurally cannot carry an instruction or an injection
    # payload — see `REASON_CODE_PATTERN`.
    reason_code: str = Field(pattern=REASON_CODE_PATTERN)
    expected_execution_id: str | None = Field(default=None, min_length=32, max_length=32)


class ExecutionView(_Strict):
    """The execution a plan concerns, as an operator may see it.

    Abstract throughout. `arguments` are the canonical validated arguments,
    which name an abstract root id and a relative path — never a physical
    directory, which lives only in wiring and inside the executor.
    """

    attempt: int
    step_id: str
    tool: str
    arguments: dict[str, object]
    execution_id: str
    side_effect_free: bool
    status: str | None = None
    # Milestone 7: the capability's content address at authorization, and
    # whether it could be compared with the live definition. An operator
    # deciding on a resume is told which of "verified" and "unverifiable" they
    # are looking at, rather than being shown one and left to assume the other.
    capability_digest: str | None = None
    capability_verified: bool = False


class RunInspection(_Strict):
    """Everything an operator may learn about a persisted run.

    Composed only of controller-derived facts. Note what is absent, and note
    that it is absent because it was never put in the journal in the first
    place rather than filtered out here: no credentials, no physical roots, no
    model reasoning or narrative, no prompts, no responses, no tool result
    payloads, and no exception text.
    """

    schema_version: int = SCHEMA_VERSION
    run_id: str
    disposition: Disposition
    reason_code: str
    plan_id: str
    max_attempts: int
    records_examined: int
    record_types: tuple[str, ...]
    terminal: bool
    terminal_status: str | None = None
    terminal_code: str | None = None
    terminal_attempts: int | None = None
    execution: ExecutionView | None = None
    available_actions: tuple[OperatorAction, ...]
    decisions_recorded: int
    next_decision_sequence: int
    operator_actions: tuple[OperatorAction, ...]
    last_action: OperatorAction | None = None
    authorization_valid: bool
    requires_operator: bool


def inspect_run(
    records: list[tuple[int, DurableRecord]],
    registry: ToolRegistry,
    run_context: RunContext,
) -> RunInspection:
    """Describe a persisted run and what may be done about it.

    A read. It validates the journal exactly as recovery does — an inspection
    of a forged journal fails rather than reporting forged facts — and then
    projects the plan onto the operator-visible surface. It executes nothing,
    persists nothing, and calls no model.
    """
    plan = plan_recovery(records, registry, run_context)
    trace = replay(records, registry, run_context)

    execution: ExecutionView | None = None
    if plan.execution_id is not None:
        # Every field here is present together or not at all: the plan only
        # carries an execution identity alongside a validated authorization.
        assert plan.step_id is not None
        assert plan.tool is not None
        assert plan.arguments is not None
        assert plan.attempt is not None
        assert plan.side_effect_free is not None
        execution = ExecutionView(
            attempt=plan.attempt,
            step_id=plan.step_id,
            tool=plan.tool,
            arguments=dict(plan.arguments),
            execution_id=plan.execution_id,
            side_effect_free=plan.side_effect_free,
            status=plan.execution_status,
            capability_digest=plan.capability_digest,
            capability_verified=plan.capability_verified,
        )

    return RunInspection(
        run_id=plan.run_id,
        disposition=plan.disposition,
        reason_code=plan.reason_code,
        plan_id=plan.plan_id,
        max_attempts=plan.max_attempts,
        records_examined=plan.records_examined,
        record_types=trace.record_types,
        terminal=plan.is_terminal,
        terminal_status=plan.terminal_status,
        terminal_code=plan.terminal_code,
        terminal_attempts=plan.terminal_attempts,
        execution=execution,
        available_actions=plan.available_actions,
        decisions_recorded=plan.decisions_recorded,
        next_decision_sequence=plan.next_decision_sequence,
        operator_actions=trace.operator_actions,
        last_action=plan.last_action,
        authorization_valid=plan.authorization_valid,
        requires_operator=plan.requires_operator,
    )


def render_inspection(inspection: RunInspection) -> str:
    """Serialize an inspection deterministically, for a machine to read.

    Sorted keys and no incidental whitespace, the same canonical form the
    journal uses: two inspections of the same records produce byte-identical
    output, so a diff between them means the run changed rather than that the
    serializer did.
    """
    return canonical_json(inspection.model_dump(mode="json"))


def validate_decision(decision: OperatorDecision, plan: RecoveryPlan) -> None:
    """Bind a decision to one exact plan, or refuse it.

    Every check compares an operator-supplied value against a value the
    controller derived from the journal moments earlier. None of them trusts
    the decision for anything; the decision's entire role is to *match*.

    Order matters only for the quality of the reason code — any single failure
    refuses the decision. Raises `OperatorDecisionRejected`; returns None when
    the decision is bound.
    """
    if decision.schema_version != SCHEMA_VERSION:
        raise OperatorDecisionRejected("decision_schema_version_unsupported")

    if decision.run_id != plan.run_id:
        # A decision made about a different run. This is the cross-run replay
        # case: an approval for run A must not act on run B, even if the two
        # plans are otherwise identical.
        raise OperatorDecisionRejected("decision_run_id_mismatch")

    if plan.is_terminal:
        # Stated separately from the action check so the reason names the real
        # cause. A terminal run has no available actions at all, so this is
        # also unreachable by any other route.
        raise OperatorDecisionRejected("run_is_terminal")

    if decision.plan_id != plan.plan_id:
        # The single most load-bearing check. A plan id covers the disposition,
        # the tool, the canonical arguments, the execution identity, the
        # budget, the available actions, and the number of decisions already
        # recorded — so this one comparison rejects a stale approval, a
        # cross-plan approval, a replayed approval, an approval made before the
        # ToolSpec or policy changed, and a plan the operator invented.
        raise OperatorDecisionRejected("decision_plan_id_mismatch")

    if decision.action not in plan.available_actions:
        raise OperatorDecisionRejected("decision_action_not_available")

    if decision.decision_sequence != plan.next_decision_sequence:
        # The sequence is controller-derived. An operator who picks their own —
        # to replay an approval, or to reserve a future slot — is refused.
        raise OperatorDecisionRejected("decision_sequence_mismatch")

    if decision.expected_execution_id != plan.execution_id:
        # Includes the None-vs-set directions: a decision naming an execution
        # for a plan that has none, or omitting one for a plan that does.
        raise OperatorDecisionRejected("decision_execution_id_mismatch")
