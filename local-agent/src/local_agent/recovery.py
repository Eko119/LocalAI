"""Deterministic recovery and observational replay (Milestone 5).

Recovery reads durable records and decides what a crashed run may do next. It
is a pure function of the journal, the live registry, and the run's frozen
`RunContext`. It never contacts the model, never asks what happened, never
reinterprets old model output, and never discovers tools — a crashed run must
be reconstructible with LocalAI switched off.

**The journal is evidence, not authority.** Every record is re-checked against
things the controller can compute for itself:

* the run id is consistent across every record;
* the recorded budget equals the live `RunContext` budget, so a journal cannot
  hand a run more attempts than it was granted;
* the tool still exists in the live registry;
* the arguments still validate against that tool's current schema;
* the execution id re-derives from run, step, attempt, tool, and arguments;
* the recorded `side_effect_free` matches the live `ToolSpec`, so a journal
  cannot declare a dangerous tool safe to repeat;
* a completion refers to an authorization that actually exists;
* nothing follows a terminal record.

Anything that fails those checks raises `RecoveryError`. There is no repair
path: authoritative state is never silently corrected.

**Replay executes nothing.** `replay` takes no executor and never reads
`ToolSpec.executor`. It reconstructs what the records say happened; it cannot
make anything happen, so a corrupted or malicious journal cannot turn an
audit into an action.

**Planning does not execute either (Milestone 6).** A `RecoveryPlan` now
carries an identity and the closed set of actions an operator may take, but it
is still only a description. The plan is *content-addressed*: its id is derived
from the same records every time, so an operator cannot construct a plan and
have it believed, and the id changes the moment any decision is recorded — an
approval therefore cannot be replayed against the plan that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from .persistence.records import (
    MAX_OPERATOR_DECISIONS_PER_RUN,
    SCHEMA_VERSION,
    DurableRecord,
    ExecutionAuthorized,
    ExecutionCompleted,
    OperatorAction,
    OperatorDecisionRecorded,
    RunStarted,
    RunTerminal,
    derive_execution_id,
    derive_plan_id,
)
from .policy import RunContext, authorize, evaluate_policy
from .registry import ToolRegistry, ToolSpec, capability_digest
from .state_machine import State

Disposition = Literal[
    # A terminal record is present: the run is over and must not execute again.
    "terminal",
    # Nothing was ever authorized: no physical execution can have happened.
    "no_execution_authorized",
    # Authorized and completed: the ambiguity window is closed.
    "execution_completed",
    # Authorized, no completion, and the tool is side-effect free: repeating it
    # adds nothing, so recovery may safely re-execute.
    "execution_pending_repeatable",
    # Authorized, no completion, and the tool is NOT side-effect free: whether
    # the effect happened is unknowable from here. Fail closed and stop.
    "execution_unknown",
]


# The controller's stable explanation of *why* a run is in this state. A code,
# not prose: it is written to the journal, shown to an operator, and compared
# in tests, and every one of those wants a value that does not drift.
DISPOSITION_REASONS: dict[Disposition, str] = {
    "terminal": "run_already_terminal",
    "no_execution_authorized": "no_execution_was_authorized",
    "execution_completed": "execution_completed_without_retained_result",
    "execution_pending_repeatable": "execution_pending_and_repeatable",
    "execution_unknown": "execution_outcome_unknown",
}

# Actions that decide nothing about execution: they record that a human looked
# at the plan. Available wherever a run is not already terminal.
_PASSIVE_ACTIONS: tuple[OperatorAction, ...] = ("acknowledge", "reject_recovery")

# Actions that end a run without executing anything.
_TERMINATING_ACTIONS: tuple[OperatorAction, ...] = ("abort", "terminalize")


class RecoveryError(Exception):
    """Recovery refused to trust the journal. Always fatal; never repaired."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class RecoveryPlan:
    """What a crashed run is permitted to do next, and on what evidence.

    Immutable, controller-generated, and content-addressed. An operator reads
    one and picks an action from `available_actions`; they never construct one,
    never edit one, and cannot make the controller believe one they built
    themselves — `plan_id` is re-derived from the journal on every use and
    compared against the id the decision names.
    """

    run_id: str
    disposition: Disposition
    max_attempts: int
    records_examined: int
    # -- identity -----------------------------------------------------------
    # Derived from every field below that decides what is being approved. Any
    # change to those — including a decision being recorded — changes the id.
    plan_id: str = ""
    plan_schema_version: int = SCHEMA_VERSION
    reason_code: str = ""
    # -- the execution this plan concerns, if any ---------------------------
    attempt: int | None = None
    step_id: str | None = None
    tool: str | None = None
    arguments: dict[str, Any] | None = None
    execution_id: str | None = None
    side_effect_free: bool | None = None
    execution_status: str | None = None
    # Milestone 7. The capability's content address as recorded at
    # authorization, and whether it could be compared against the live
    # definition at all. `False` means the record predates capability digests,
    # not that a comparison failed — a mismatch is fatal and never reaches a
    # plan. Keeping the two apart is the difference between "verified" and
    # "unverifiable", which an operator deciding on a resume needs to know.
    capability_digest: str | None = None
    capability_verified: bool = False
    # -- terminal facts, if the run already ended ---------------------------
    terminal_status: str | None = None
    terminal_code: str | None = None
    terminal_attempts: int | None = None
    # -- operator control plane ---------------------------------------------
    # Exactly the actions valid for this controller-derived state. An action
    # absent from this tuple has no code path, not merely no permission.
    available_actions: tuple[OperatorAction, ...] = ()
    # How many decisions this run has already recorded, and therefore which
    # sequence the next one must carry. Both are controller-derived; an
    # operator who picks their own sequence is refused.
    decisions_recorded: int = 0
    next_decision_sequence: int = 1
    last_action: OperatorAction | None = None
    # Whether the original operation still passes AUTHORIZE and POLICY *now*,
    # against the live registry and the live RunContext. A run whose grants
    # were narrowed after the crash is not resumable, and this is where that
    # is decided rather than at the executor.
    authorization_valid: bool = False

    @property
    def may_execute(self) -> bool:
        """Whether recovery is allowed to invoke an executor.

        Note this is now a statement about the *plan*, not a permission: it is
        true only where the controller both established that repeating the
        execution adds no further effect and re-confirmed the gates. An
        operator decision is still required on top of it; nothing executes
        because this is true.
        """
        return "resume" in self.available_actions

    @property
    def requires_operator(self) -> bool:
        """Whether a human must decide, because the system cannot know."""
        return self.disposition == "execution_unknown"

    @property
    def is_terminal(self) -> bool:
        """A terminal run offers no actions at all. Terminality is immutable."""
        return self.disposition == "terminal"


@dataclass(frozen=True)
class ReplayResult:
    """The observable reconstruction of a run. Produced without executing."""

    run_id: str
    states: tuple[State, ...]
    record_types: tuple[str, ...]
    execution_ids: tuple[str, ...]
    executions_completed: int
    terminal_status: str | None
    terminal_code: str | None
    attempts: int | None
    # Milestone 6: the operator decisions the run recorded, in order. Actions
    # and sequences only — no reason codes, no plan bodies. A replay is a
    # reconstruction of control flow, not a transcript of the control plane.
    operator_actions: tuple[OperatorAction, ...] = ()


def _validate_sequence(records: list[tuple[int, DurableRecord]], run_context: RunContext) -> str:
    """Structural checks that do not depend on the registry."""
    if not records:
        raise RecoveryError("journal_empty")

    first = records[0][1]
    if not isinstance(first, RunStarted):
        raise RecoveryError("journal_missing_run_started")

    if first.run_id != run_context.run_id:
        raise RecoveryError("journal_run_id_mismatch")

    # A journal may not grant a larger budget than the run actually holds.
    if first.max_attempts != run_context.max_attempts:
        raise RecoveryError("journal_budget_mismatch")

    seen_terminal = False
    for _, record in records:
        if record.run_id != run_context.run_id:
            raise RecoveryError("journal_run_id_mismatch")
        if seen_terminal:
            # Nothing may follow the end of a run: a record after a terminal
            # is either corruption or an attempt to resurrect a closed run.
            raise RecoveryError("journal_record_after_terminal")
        if isinstance(record, RunTerminal):
            seen_terminal = True
        if isinstance(record, RunStarted) and record is not first:
            raise RecoveryError("journal_duplicate_run_started")

    return first.run_id


def _validate_authorization(
    record: ExecutionAuthorized, registry: ToolRegistry, run_context: RunContext
) -> tuple[ToolSpec, BaseModel]:
    """Re-derive and re-validate everything the record claims.

    Returns the live `ToolSpec` and the re-validated arguments so the caller
    can run the gates against them. Note the direction: the record is checked
    *against* the live registry, never the other way round.
    """
    if not 1 <= record.attempt <= run_context.max_attempts:
        raise RecoveryError("journal_attempt_out_of_range")

    spec = registry.get(record.tool)
    if spec is None:
        # The tool named in the journal does not exist in the live registry:
        # either the record was altered, or the registry changed underneath a
        # crashed run. Either way, recovery must not proceed.
        raise RecoveryError("journal_tool_not_in_registry")

    try:
        args = spec.args_schema.model_validate(record.arguments)
    except ValidationError as exc:
        raise RecoveryError("journal_arguments_invalid") from exc

    # The journal cannot declare a tool safe to repeat. The live ToolSpec is
    # the authority for that, and a disagreement means the record was altered.
    if record.side_effect_free != spec.side_effect_free:
        raise RecoveryError("journal_side_effect_flag_mismatch")

    # The capability's *definition* must be the one that was authorized
    # (Milestone 7). This catches what nothing else does: a schema widened, a
    # timeout raised, an authorization requirement dropped — changes that leave
    # the recorded arguments valid and the execution identity intact while
    # meaning something different from what the run was granted.
    #
    # A record with no digest predates the field. It is *not* treated as
    # verified: `plan_recovery` reports `capability_verified=False` so the
    # difference between "checked and matched" and "could not be checked" stays
    # visible to whoever is deciding what to do next.
    if record.capability_digest is not None and record.capability_digest != capability_digest(spec):
        raise RecoveryError("journal_capability_digest_mismatch")

    # Re-derivation is what makes an altered tool name, argument, or attempt
    # detectable without needing an authenticated log.
    expected = derive_execution_id(
        record.run_id,
        record.step_id,
        record.attempt,
        record.tool,
        args.model_dump(mode="json"),
    )
    if expected != record.execution_id:
        raise RecoveryError("journal_execution_id_mismatch")

    return spec, args


def _validate_decisions(
    records: list[tuple[int, DurableRecord]],
) -> list[OperatorDecisionRecorded]:
    """Structural checks over the operator decisions in a journal.

    Sequences must start at 1 and increase by exactly one. A gap would let a
    journal be edited to make a *future* sequence look already-used, and a
    repeat would let one approval stand in for two.
    """
    decisions = [record for _, record in records if isinstance(record, OperatorDecisionRecorded)]
    if len(decisions) > MAX_OPERATOR_DECISIONS_PER_RUN:
        raise RecoveryError("journal_operator_decision_ceiling_exceeded")
    for index, decision in enumerate(decisions, start=1):
        if decision.decision_sequence != index:
            raise RecoveryError("journal_operator_decision_sequence_invalid")
    return decisions


def _available_actions(
    disposition: Disposition, *, authorization_valid: bool, decisions: int
) -> tuple[OperatorAction, ...]:
    """The closed set of actions valid for this controller-derived state.

    Three deliberate restrictions live here, and each is a fail-closed choice:

    * a **terminal** run offers nothing at all, so there is no action an
      operator could take that would resurrect it;
    * **`execution_unknown` does not offer `resume`.** The tool is not
      side-effect free and the journal cannot say whether the effect happened,
      so re-running it might duplicate a real side effect. The operator is not
      permitted to overrule that, because doing so would be exactly the
      "operator changes `side_effect_free`" move the threat model forbids. The
      cost is real: an operator who *knows* the effect did not happen still
      cannot resume, and must start a new run instead;
    * **`execution_completed` does not offer `resume`.** The physical call
      finished, but the journal deliberately never stored the result, so the
      run cannot be verified without executing a second time.
    """
    if disposition == "terminal":
        return ()
    if decisions >= MAX_OPERATOR_DECISIONS_PER_RUN:
        # The control plane is bounded like everything else that persists.
        return ()
    actions: tuple[OperatorAction, ...] = ()
    if disposition == "execution_pending_repeatable" and authorization_valid:
        actions += ("resume",)
    return actions + _TERMINATING_ACTIONS + _PASSIVE_ACTIONS


def _plan_identity(fields: dict[str, Any]) -> str:
    """Derive a plan id from every field that decides what is being approved."""
    return derive_plan_id({"plan_schema_version": SCHEMA_VERSION, **fields})


def _build_plan(**fields: Any) -> RecoveryPlan:
    """Assemble a plan and stamp it with its own content address.

    The id covers the whole plan, `decisions_recorded` included. That is what
    makes staleness structural: recording any decision changes the plan, so the
    approval that produced it no longer names a plan that exists.
    """
    material = {key: value for key, value in fields.items() if key != "records_examined"}
    material["available_actions"] = list(fields.get("available_actions", ()))
    return RecoveryPlan(plan_id=_plan_identity(material), **fields)


def plan_recovery(
    records: list[tuple[int, DurableRecord]],
    registry: ToolRegistry,
    run_context: RunContext,
) -> RecoveryPlan:
    """Decide what a crashed run may do next. Pure; contacts nothing.

    Reads the journal, re-validates every record against live authority, and
    returns a description. It invokes no executor, calls no model, and mutates
    nothing — acting on the plan is a separate, explicitly authorized step.
    """
    run_id = _validate_sequence(records, run_context)
    decisions = _validate_decisions(records)

    authorizations: dict[str, ExecutionAuthorized] = {}
    completions: dict[str, ExecutionCompleted] = {}
    validated: dict[str, tuple[ToolSpec, BaseModel]] = {}
    terminal: RunTerminal | None = None

    for _, record in records:
        if isinstance(record, ExecutionAuthorized):
            validated[record.execution_id] = _validate_authorization(record, registry, run_context)
            if record.execution_id in authorizations:
                raise RecoveryError("journal_duplicate_authorization")
            authorizations[record.execution_id] = record
        elif isinstance(record, ExecutionCompleted):
            if record.execution_id not in authorizations:
                # A completion with no authorization is a forged result: it
                # claims an execution the controller never approved.
                raise RecoveryError("journal_completion_without_authorization")
            if record.execution_id in completions:
                raise RecoveryError("journal_duplicate_completion")
            completions[record.execution_id] = record
        elif isinstance(record, RunTerminal):
            terminal = record

    examined = len(records)
    recorded = len(decisions)
    common: dict[str, Any] = {
        "run_id": run_id,
        "max_attempts": run_context.max_attempts,
        "records_examined": examined,
        "decisions_recorded": recorded,
        "next_decision_sequence": recorded + 1,
        "last_action": decisions[-1].action if decisions else None,
    }

    if terminal is not None:
        return _build_plan(
            **common,
            disposition="terminal",
            reason_code=DISPOSITION_REASONS["terminal"],
            available_actions=_available_actions(
                "terminal", authorization_valid=False, decisions=recorded
            ),
            authorization_valid=False,
            terminal_status=terminal.status,
            terminal_code=terminal.code,
            terminal_attempts=terminal.attempts,
        )

    pending = [
        authorization
        for execution_id, authorization in authorizations.items()
        if execution_id not in completions
    ]
    if len(pending) > 1:
        # The controller authorizes one execution at a time, so more than one
        # outstanding authorization means the journal does not describe a run
        # this controller could have produced.
        raise RecoveryError("journal_multiple_pending_executions")

    if pending:
        authorization = pending[0]
        disposition: Disposition = (
            "execution_pending_repeatable"
            if authorization.side_effect_free
            else "execution_unknown"
        )
        spec, args = validated[authorization.execution_id]
        # The gates are re-run here, not merely remembered. A run whose grants
        # or policy ceilings were narrowed after the crash must not be offered
        # a resume it would only be refused at EXECUTE.
        valid = (
            authorize(spec, args, run_context).allowed
            and evaluate_policy(spec, args, run_context).allowed
        )
        return _build_plan(
            **common,
            disposition=disposition,
            reason_code=DISPOSITION_REASONS[disposition],
            available_actions=_available_actions(
                disposition, authorization_valid=valid, decisions=recorded
            ),
            authorization_valid=valid,
            attempt=authorization.attempt,
            step_id=authorization.step_id,
            tool=authorization.tool,
            arguments=authorization.arguments,
            execution_id=authorization.execution_id,
            side_effect_free=authorization.side_effect_free,
            capability_digest=authorization.capability_digest,
            capability_verified=authorization.capability_digest is not None,
        )

    if authorizations:
        last_id = list(authorizations)[-1]
        completion = completions[last_id]
        authorization = authorizations[last_id]
        return _build_plan(
            **common,
            disposition="execution_completed",
            reason_code=DISPOSITION_REASONS["execution_completed"],
            available_actions=_available_actions(
                "execution_completed", authorization_valid=False, decisions=recorded
            ),
            authorization_valid=False,
            attempt=authorization.attempt,
            step_id=authorization.step_id,
            tool=authorization.tool,
            arguments=authorization.arguments,
            execution_id=last_id,
            side_effect_free=authorization.side_effect_free,
            execution_status=completion.status,
            capability_digest=authorization.capability_digest,
            capability_verified=authorization.capability_digest is not None,
        )

    return _build_plan(
        **common,
        disposition="no_execution_authorized",
        reason_code=DISPOSITION_REASONS["no_execution_authorized"],
        available_actions=_available_actions(
            "no_execution_authorized", authorization_valid=False, decisions=recorded
        ),
        authorization_valid=False,
    )


def replay(
    records: list[tuple[int, DurableRecord]],
    registry: ToolRegistry,
    run_context: RunContext,
) -> ReplayResult:
    """Reconstruct a run's observable shape from its journal, executing nothing.

    Note what this function does not take and does not touch: no executor, no
    adapter, no transport. It reads `registry` only to re-validate records via
    `plan_recovery`, never to reach `ToolSpec.executor`. A malicious journal
    therefore has nothing here to trigger.
    """
    # Re-validate first: replaying an untrusted journal must not be a way to
    # bypass the checks that recovery applies.
    plan_recovery(records, registry, run_context)

    states: list[State] = [State.RECEIVE]
    record_types: list[str] = []
    execution_ids: list[str] = []
    completed = 0
    operator_actions: list[OperatorAction] = []
    terminal_status: str | None = None
    terminal_code: str | None = None
    attempts: int | None = None

    for _, record in records:
        record_types.append(record.type)
        if isinstance(record, RunStarted):
            states.extend((State.CLASSIFY, State.GENERATE))
        elif isinstance(record, ExecutionAuthorized):
            execution_ids.append(record.execution_id)
            states.extend(
                (
                    State.PARSE,
                    State.VALIDATE,
                    State.AUTHORIZE,
                    State.POLICY_CHECK,
                    State.EXECUTE,
                )
            )
        elif isinstance(record, ExecutionCompleted):
            completed += 1
            states.append(State.VERIFY if record.status == "succeeded" else State.FEEDBACK)
        elif isinstance(record, OperatorDecisionRecorded):
            # A decision is not a state transition. Recording one moves nothing
            # through the state machine; only acting on it does, and acting is
            # the controller's job, not replay's.
            operator_actions.append(record.action)
        elif isinstance(record, RunTerminal):
            terminal_status = record.status
            terminal_code = record.code
            attempts = record.attempts
            states.append(State.TERMINAL)

    return ReplayResult(
        run_id=run_context.run_id,
        states=tuple(states),
        record_types=tuple(record_types),
        execution_ids=tuple(execution_ids),
        executions_completed=completed,
        terminal_status=terminal_status,
        terminal_code=terminal_code,
        attempts=attempts,
        operator_actions=tuple(operator_actions),
    )
