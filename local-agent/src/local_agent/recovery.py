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
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import ValidationError

from .persistence.records import (
    DurableRecord,
    ExecutionAuthorized,
    ExecutionCompleted,
    RunStarted,
    RunTerminal,
    derive_execution_id,
)
from .policy import RunContext
from .registry import ToolRegistry
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


class RecoveryError(Exception):
    """Recovery refused to trust the journal. Always fatal; never repaired."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class RecoveryPlan:
    """What a crashed run is permitted to do next, and on what evidence."""

    run_id: str
    disposition: Disposition
    max_attempts: int
    records_examined: int
    attempt: int | None = None
    tool: str | None = None
    arguments: dict[str, Any] | None = None
    execution_id: str | None = None
    side_effect_free: bool | None = None
    execution_status: str | None = None
    terminal_status: str | None = None
    terminal_code: str | None = None
    terminal_attempts: int | None = None

    @property
    def may_execute(self) -> bool:
        """Whether recovery is allowed to invoke an executor.

        True in exactly one case: an authorized, uncompleted execution of a
        tool whose repetition has no additional effect.
        """
        return self.disposition == "execution_pending_repeatable"

    @property
    def requires_operator(self) -> bool:
        """Whether a human must decide, because the system cannot know."""
        return self.disposition == "execution_unknown"


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
) -> None:
    """Re-derive and re-validate everything the record claims."""
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


def plan_recovery(
    records: list[tuple[int, DurableRecord]],
    registry: ToolRegistry,
    run_context: RunContext,
) -> RecoveryPlan:
    """Decide what a crashed run may do next. Pure; contacts nothing."""
    run_id = _validate_sequence(records, run_context)

    authorizations: dict[str, ExecutionAuthorized] = {}
    completions: dict[str, ExecutionCompleted] = {}
    terminal: RunTerminal | None = None

    for _, record in records:
        if isinstance(record, ExecutionAuthorized):
            _validate_authorization(record, registry, run_context)
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

    if terminal is not None:
        return RecoveryPlan(
            run_id=run_id,
            max_attempts=run_context.max_attempts,
            records_examined=examined,
            disposition="terminal",
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
        return RecoveryPlan(
            run_id=run_id,
            max_attempts=run_context.max_attempts,
            records_examined=examined,
            disposition=(
                "execution_pending_repeatable"
                if authorization.side_effect_free
                else "execution_unknown"
            ),
            attempt=authorization.attempt,
            tool=authorization.tool,
            arguments=authorization.arguments,
            execution_id=authorization.execution_id,
            side_effect_free=authorization.side_effect_free,
        )

    if authorizations:
        last_id = list(authorizations)[-1]
        completion = completions[last_id]
        authorization = authorizations[last_id]
        return RecoveryPlan(
            run_id=run_id,
            max_attempts=run_context.max_attempts,
            records_examined=examined,
            disposition="execution_completed",
            attempt=authorization.attempt,
            tool=authorization.tool,
            arguments=authorization.arguments,
            execution_id=last_id,
            side_effect_free=authorization.side_effect_free,
            execution_status=completion.status,
        )

    return RecoveryPlan(
        run_id=run_id,
        max_attempts=run_context.max_attempts,
        records_examined=examined,
        disposition="no_execution_authorized",
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
    )
