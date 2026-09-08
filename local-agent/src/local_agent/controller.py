"""The deterministic controller.

This is the only component with authority. It owns the state machine, the
registry, the retry budget, and the decision to execute. The model's entire
influence on it is one string on one channel (`ModelResponse.structured_output`),
which is parsed, schema-validated, authorized, policy-checked, executed, and
verified before anything happens — and any of those gates can end the run.

Pipeline (spec §"architecture"):

    RAW MODEL OUTPUT -> PARSE -> CANDIDATE -> SCHEMA VALIDATION
    -> AUTHORIZATION -> POLICY -> BUDGET -> EXECUTION -> VERIFICATION -> RESPONSE

Every stage transition goes through `Run.advance`, so an implementation bug
that tried to skip a gate (say, PARSE straight to EXECUTE) raises
`IllegalStateTransitionError` rather than quietly executing.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from .contracts import (
    COMPLETION_TOOL,
    RETRYABLE_CODES,
    ControllerError,
    ControllerTerminal,
    ErrorCode,
    ExecutionComplete,
    ModelRequest,
    ModelResponse,
    RawToolCall,
    ToolFeedback,
)
from .events import Event, EventRecorder
from .model_adapter import (
    ModelAdapter,
    ModelResponseInvalid,
    ModelTransportError,
    ModelTransportTimeout,
)
from .operator import OperatorDecision, validate_decision
from .persistence.journal import RunJournal
from .persistence.records import (
    DurableRecord,
    ExecutionAuthorized,
    ExecutionCompleted,
    JournalError,
    OperatorAction,
    OperatorDecisionRecorded,
    RunStarted,
    RunTerminal,
    derive_execution_id,
)
from .policy import RunContext, authorize, evaluate_policy
from .recovery import Disposition, RecoveryPlan, plan_recovery
from .registry import (
    ToolDenialError,
    ToolExecutionError,
    ToolRegistry,
    ToolSpec,
    capability_digest,
)
from .state_machine import Run, State

# Model-facing wording. Deliberately terse and gate-agnostic: a denial must
# not teach the model which gate it hit or how to satisfy it next time
# (spec §"feedback_security"). Schema messages are the exception — those
# must be actionable enough to repair an honest mistake.
_DENIED_MESSAGE = "The request was denied by controller policy."
_MALFORMED_MESSAGE = "No valid structured tool call was produced on the approved channel."
_UNKNOWN_TOOL_MESSAGE = "The requested tool is not available."
_SCHEMA_MESSAGE = "Tool arguments failed schema validation."
_TIMEOUT_MESSAGE = "The tool call exceeded its execution time budget."
_EXECUTION_MESSAGE = "The tool could not complete the request."
_VERIFICATION_MESSAGE = "The tool returned a result that failed verification."
_MODEL_TIMEOUT_MESSAGE = "The model service did not respond in time."
_MODEL_UNAVAILABLE_MESSAGE = "The model service could not be reached."
_MODEL_RESPONSE_MESSAGE = "The model service returned an unusable response."


class _Rejection(Exception):
    """Internal control-flow signal: one gate rejected the current attempt.

    Carries only already-sanitized, model-safe content. Raising this is how a
    gate says "reject"; it never carries an upstream exception's message,
    because those can contain host paths or internals.
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        field_errors: list[dict[str, object]] | None = None,
    ) -> None:
        self.code: ErrorCode = code
        self.message = message
        self.field_errors = field_errors or []
        super().__init__(message)


def parse_candidate(response: ModelResponse) -> RawToolCall | ExecutionComplete:
    """The parser boundary (spec §"reasoning_boundary", 08 Correction 4).

    Only `response.structured_output` is eligible. `reasoning` and `narrative`
    are never read here — not filtered, not scanned, not stripped: simply not
    an input to this function. A tool call that exists only inside reasoning
    is therefore invisible to the controller by construction, which is a
    stronger property than any text heuristic could give.
    """
    raw = response.structured_output
    if raw is None or not raw.strip():
        raise _Rejection("TOOL_CALL_MALFORMED", _MALFORMED_MESSAGE)

    try:
        payload: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        # The decoder's message is not forwarded: it echoes model text back
        # and adds nothing the model needs to emit valid JSON next time.
        raise _Rejection("TOOL_CALL_MALFORMED", _MALFORMED_MESSAGE) from exc

    if not isinstance(payload, dict):
        # Also the answer to "multiple competing tool calls": a JSON array of
        # calls is not a single envelope, so it never becomes a candidate.
        raise _Rejection("TOOL_CALL_MALFORMED", _MALFORMED_MESSAGE)

    if payload.get("tool") == COMPLETION_TOOL:
        # Milestone 10. The structured channel now carries two shapes, and the
        # discriminator is a reserved capability name — the only discriminator
        # the production adapter can actually emit, since it builds its output
        # from `message.tool_calls`.
        #
        # Routed here *before* a `RawToolCall` is constructed, so a completion
        # never becomes a proposal. Nothing can be called this: `registry.admit`
        # refuses the name, so it can never resolve to a capability, and a
        # completion carrying arguments is refused as malformed rather than
        # treated as a call.
        #
        # This is one parser, not two. Architecture rule 10 forbids a second
        # parser beside this function.
        try:
            return ExecutionComplete.model_validate(payload)
        except ValidationError as exc:
            raise _Rejection("TOOL_CALL_MALFORMED", _MALFORMED_MESSAGE) from exc

    try:
        return RawToolCall.model_validate(payload)
    except ValidationError as exc:
        # RawToolCall forbids extra fields, so an envelope carrying smuggled
        # control fields (`max_attempts`, `authorized`, ...) lands here.
        raise _Rejection("TOOL_CALL_MALFORMED", _MALFORMED_MESSAGE) from exc


def _sanitize_validation_errors(exc: ValidationError) -> list[dict[str, object]]:
    """Reduce a pydantic error set to `{field, reason}` pairs.

    Drops pydantic's `input` (which echoes model-supplied values, possibly
    huge), `url`, and `ctx`. What survives states the constraint that was
    violated, which is what a legitimate repair attempt needs.
    """
    sanitized: list[dict[str, object]] = []
    for error in exc.errors():
        field = ".".join(str(part) for part in error["loc"]) or "(root)"
        sanitized.append({"field": field, "reason": error["msg"]})
    return sanitized


class RecoveryRefused(Exception):
    """The controller refused to act on a recovery decision.

    Distinct from `OperatorDecisionRejected`, which means the decision did not
    bind to the plan. This means the decision bound, was recorded, and then the
    world failed re-validation between recording and execution — or that
    recovery was asked of a controller with no durable state to recover from.

    `reason` is a stable slug. It is safe to show an operator and never reaches
    a model, because nothing on this path talks to one.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class _ResumeSeed:
    """One authorized-but-uncompleted execution, ready to re-enter the loop.

    Carries the *original* operation: the tool the controller resolved from the
    live registry, the canonical arguments re-validated against that tool's
    current schema, and the execution identity re-derived from both. Nothing
    here came from the operator, and nothing here is a new authorization — the
    write-ahead record already on disk is the authorization, which is why
    resuming does not write a second one.
    """

    spec: ToolSpec
    args: BaseModel
    step_id: str
    attempt: int
    execution_id: str


@dataclass(frozen=True)
class RecoveryOutcome:
    """What the controller did about one operator decision.

    Operator-facing, not model-facing. It exists because the operator needs to
    know what happened; nothing in it is ever shown to a model, and the
    ordinary `RunOutcome` a resume produces is the same shape an uninterrupted
    run produces, so recovery adds no second model protocol.
    """

    run_id: str
    action: OperatorAction
    plan_id: str
    decision_sequence: int
    disposition: Disposition
    reason_code: str
    resulting_state: str
    terminal: bool
    terminal_status: str | None = None
    executed: bool = False
    execution_id: str | None = None
    run: RunOutcome | None = None


@dataclass(frozen=True)
class RunOutcome:
    """Everything a caller (or a test) needs to audit one run."""

    terminal: ControllerTerminal
    states: tuple[State, ...]
    events: tuple[Event, ...]
    attempts: int
    result: BaseModel | None = None
    error: ControllerError | None = None
    # Milestone 10: how many executions this run actually composed. Distinct
    # from `attempts`, which counts tries at the final execution.
    executions: int = 0

    @property
    def succeeded(self) -> bool:
        return self.terminal.status == "succeeded"


class Controller:
    """Owns the run. Constructed by trusted wiring, never by model output."""

    def __init__(
        self,
        registry: ToolRegistry,
        adapter: ModelAdapter,
        journal: RunJournal | None = None,
    ) -> None:
        self._registry = registry
        self._adapter = adapter
        # Optional by design: a run without a journal behaves exactly as it did
        # before Milestone 5, which is why every existing test still passes
        # unchanged. A run *with* one becomes recoverable.
        self._journal = journal

    async def run(
        self,
        run_context: RunContext,
        messages: Sequence[dict[str, str]],
    ) -> RunOutcome:
        recorder = EventRecorder(run_context.run_id)
        machine = Run()
        recorder.record("run_created", max_attempts=run_context.max_attempts)
        self._persist(
            RunStarted(
                run_id=run_context.run_id,
                max_attempts=run_context.max_attempts,
                max_executions=run_context.max_executions,
            )
        )
        recorder.record("state_entered", state=State.RECEIVE.value)

        self._enter(machine, recorder, State.CLASSIFY)
        self._enter(machine, recorder, State.GENERATE)

        return await self._loop(run_context, messages, machine, recorder, seed=None)

    async def _loop(
        self,
        run_context: RunContext,
        messages: Sequence[dict[str, str]],
        machine: Run,
        recorder: EventRecorder,
        *,
        seed: _ResumeSeed | None,
    ) -> RunOutcome:
        """The attempt loop. One entry point for a fresh run and for a resume.

        `seed` is the only difference between the two. When it is present the
        first iteration takes its operation from the journal instead of the
        model — the states walked, the gates run, the verification applied and
        the continuation that follows are all the ordinary ones. There is no
        recovery-specific execution path, and that is deliberate: a second path
        would be a second place for a gate to be forgotten.
        """
        # COMPOSITION STATE (Milestone 10). `execution_index` counts authorized
        # executions, not attempts: a retry of E2 stays inside E2's attempt
        # sequence and keeps `-s2`. The counter is controller-owned and derives
        # from nothing external — no clock, no UUID, no model output — which is
        # what makes step identity deterministic across repetitions.
        execution_index = 1
        step_id = seed.step_id if seed is not None else f"{run_context.run_id}-s1"
        attempt = seed.attempt if seed is not None else 1
        feedback: ToolFeedback | None = None
        last_error: ControllerError | None = None
        # A resumed run finishes the execution it was resumed for and stops.
        # Milestone 6 established that a successful resume terminates through
        # RESPOND -> TERMINAL and explicitly deferred "manufacture another model
        # generation after recovery"; composing further would do exactly that,
        # against a run the model never saw. Recorded as deferred, not silently
        # changed.
        resumed_run = seed is not None
        executions_completed = 0
        last_result: BaseModel | None = None
        last_execution_attempts = 1

        while True:
            tool_call_id = f"{step_id}-a{attempt}"
            tool_name = "unknown"
            # The capability whose executor was actually invoked on this
            # attempt, or None if the attempt was rejected before EXECUTE.
            # Retry eligibility depends on it: repeating a capability that
            # already ran is a different question from repeating a proposal
            # that never did.
            invoked: ToolSpec | None = None

            try:
                if seed is not None:
                    # RESUMED ITERATION. The operation is already known and
                    # already durably authorized, so no generation is requested
                    # and no model output is parsed. The states are still
                    # walked, because this run really did pass through them
                    # before it crashed — the same run is continuing, not a new
                    # one skipping gates. Everything below this branch is the
                    # ordinary path, shared byte-for-byte with a fresh run.
                    spec, args = seed.spec, seed.args
                    tool_name = spec.name
                    resumed_execution_id: str | None = seed.execution_id
                    seed = None
                    self._enter(machine, recorder, State.PARSE)
                    self._enter(machine, recorder, State.VALIDATE)
                    recorder.record("recovery_resumed", tool=tool_name, attempt=attempt)
                else:
                    resumed_execution_id = None
                    request = ModelRequest(
                        run_id=run_context.run_id,
                        step_id=step_id,
                        attempt=attempt,
                        messages=tuple(messages),
                        feedback=feedback,
                    )
                    try:
                        response = await self._adapter.chat(request)
                    except ModelTransportTimeout as exc:
                        recorder.record("model_call_failed", attempt=attempt, reason=exc.reason)
                        raise _Rejection("EXECUTION_TIMEOUT", _MODEL_TIMEOUT_MESSAGE) from exc
                    except ModelTransportError as exc:
                        recorder.record("model_call_failed", attempt=attempt, reason=exc.reason)
                        raise _Rejection("EXECUTION_FAILED", _MODEL_UNAVAILABLE_MESSAGE) from exc
                    except ModelResponseInvalid as exc:
                        recorder.record("model_call_failed", attempt=attempt, reason=exc.reason)
                        raise _Rejection("VERIFICATION_FAILED", _MODEL_RESPONSE_MESSAGE) from exc
                    # Any other exception from an adapter is a programmer error
                    # and propagates on purpose, as it does for an executor.

                    recorder.record(
                        "model_output_received",
                        attempt=attempt,
                        # Structural facts only — never the generated text.
                        has_structured_output=response.structured_output is not None,
                        has_reasoning=response.reasoning is not None,
                    )

                    self._enter(machine, recorder, State.PARSE)
                    candidate = parse_candidate(response)

                    if isinstance(candidate, ExecutionComplete) and feedback is not None:
                        # COMPLETION IS NOT A REPAIR.
                        #
                        # The controller asks two different questions and the
                        # valid answers differ. After a rejection it asks
                        # "repair this proposal"; after a successful execution
                        # it asks "anything else?". Only the second admits a
                        # completion.
                        #
                        # Without this the model could launder a refusal into a
                        # success: told its proposal was denied, it answers
                        # "complete" and the run reports `succeeded`. That is
                        # the model deciding a run's outcome, which is the one
                        # thing every gate in this pipeline exists to prevent.
                        #
                        # The run therefore ends on the error that was actually
                        # outstanding, not on a new one about the completion.
                        # The failure is the proposal nobody repaired; saying
                        # "I am finished" did not create a second, different
                        # problem, and reporting one would bury the real cause.
                        assert last_error is not None  # feedback implies a prior rejection
                        recorder.record("completion_rejected_during_repair", attempt=attempt)
                        self._enter(machine, recorder, State.FEEDBACK)
                        self._enter(machine, recorder, State.TERMINAL)
                        recorder.record(
                            "terminal", status="failed", code=last_error.code, attempts=attempt
                        )
                        self._persist(
                            RunTerminal(
                                run_id=run_context.run_id,
                                status="failed",
                                code=last_error.code,
                                attempts=attempt,
                            )
                        )
                        return RunOutcome(
                            terminal=ControllerTerminal(
                                status="failed", code=last_error.code, attempts=attempt
                            ),
                            states=tuple(machine.history),
                            events=recorder.snapshot(),
                            attempts=attempt,
                            error=last_error,
                            executions=executions_completed,
                        )

                    if isinstance(candidate, ExecutionComplete):
                        # CASE B: affirmative completion at a composition
                        # boundary. The model stated that no further execution
                        # is required, so the run ends successfully. It requires
                        # a positive statement — absence still lands in the
                        # malformed branch, unchanged.
                        recorder.record(
                            "execution_complete_declared",
                            executions=executions_completed,
                            attempt=attempt,
                        )
                        self._enter(machine, recorder, State.TERMINAL)
                        recorder.record(
                            "terminal", status="succeeded", attempts=last_execution_attempts
                        )
                        self._persist(
                            RunTerminal(
                                run_id=run_context.run_id,
                                status="succeeded",
                                attempts=last_execution_attempts,
                            )
                        )
                        return RunOutcome(
                            terminal=ControllerTerminal(
                                status="succeeded", code=None, attempts=last_execution_attempts
                            ),
                            states=tuple(machine.history),
                            events=recorder.snapshot(),
                            attempts=last_execution_attempts,
                            result=last_result,
                            executions=executions_completed,
                        )

                    if execution_index > run_context.max_executions:
                        # CASE C: a further execution was requested and the
                        # run's composition ceiling is already consumed.
                        #
                        # Checked HERE — after parsing, before VALIDATE,
                        # AUTHORIZE, POLICY_CHECK and the executor — so a
                        # request for execution N+1 never reaches any of them.
                        # `POLICY_DENIED` is not in `RETRYABLE_CODES`, so this
                        # consumes no retry budget and increments no attempt
                        # counter: the ceiling is not a failure of *this*
                        # execution, it is the run's capacity running out.
                        recorder.record(
                            "execution_ceiling_exhausted",
                            requested=execution_index,
                            max_executions=run_context.max_executions,
                        )
                        raise _Rejection("POLICY_DENIED", _DENIED_MESSAGE)

                    tool_name = candidate.tool
                    recorder.record("candidate_parsed", tool=tool_name, attempt=attempt)

                    self._enter(machine, recorder, State.VALIDATE)
                    spec, args = self._validate(candidate, recorder)

                self._enter(machine, recorder, State.AUTHORIZE)
                self._authorize(spec, args, run_context, recorder)

                self._enter(machine, recorder, State.POLICY_CHECK)
                self._policy(spec, args, run_context, recorder)

                self._enter(machine, recorder, State.EXECUTE)
                if resumed_execution_id is not None:
                    # The write-ahead record already on disk is still the
                    # authorization for this execution. Writing a second one
                    # would forge an authorization the controller never made,
                    # and recovery would reject the journal for it.
                    execution_id = resumed_execution_id
                else:
                    # WRITE-AHEAD BOUNDARY. The authorization is durable before
                    # the executor is invoked, so a crash *during* execution is
                    # detectable: the journal then holds an authorization with
                    # no matching completion. Without this ordering the
                    # ambiguous window would be silent rather than ambiguous.
                    execution_id = derive_execution_id(
                        run_context.run_id,
                        step_id,
                        attempt,
                        spec.name,
                        args.model_dump(mode="json"),
                    )
                    self._persist_authorization(
                        ExecutionAuthorized(
                            run_id=run_context.run_id,
                            step_id=step_id,
                            attempt=attempt,
                            tool=spec.name,
                            arguments=args.model_dump(mode="json"),
                            execution_id=execution_id,
                            side_effect_free=spec.side_effect_free,
                            capability_digest=capability_digest(spec),
                        ),
                        recorder,
                    )
                # From here on a physical effect may have occurred, so this
                # is set before the call rather than after it.
                invoked = spec
                try:
                    raw_result = self._execute(spec, args, tool_call_id, attempt, recorder)
                except _Rejection as rejection:
                    # The executor ran and failed. Recording completion closes
                    # the ambiguity window: recovery knows the physical call
                    # finished, even though it finished badly.
                    self._persist(
                        ExecutionCompleted(
                            run_id=run_context.run_id,
                            execution_id=execution_id,
                            status="failed",
                            reason=rejection.code,
                        )
                    )
                    raise
                self._persist(
                    ExecutionCompleted(
                        run_id=run_context.run_id,
                        execution_id=execution_id,
                        status="succeeded",
                    )
                )

                self._enter(machine, recorder, State.VERIFY)
                result = self._verify(spec, raw_result, recorder)

            except _Rejection as rejection:
                error = ControllerError(
                    code=rejection.code,
                    retryable=rejection.code in RETRYABLE_CODES,
                    retry_budget_remaining=run_context.max_attempts - attempt,
                    message=rejection.message,
                    field_errors=rejection.field_errors,
                    attempt=attempt,
                    max_attempts=run_context.max_attempts,
                )
                last_error = error

                self._enter(machine, recorder, State.FEEDBACK)

                # CAPABILITY GATE (Milestone 7). Retryability of an *error* and
                # re-executability of a *capability* are different questions,
                # and before this gate existed only the first was asked — so a
                # failing `MUTATING` capability was re-run up to `max_attempts`
                # times, compounding its effect once per attempt. Measured, not
                # theorised: three physical side effects for a budget of three.
                #
                # `invoked is None` means the attempt was rejected before the
                # executor was reached, so nothing happened and the ordinary
                # retry rules apply unchanged.
                capability_permits_retry = invoked is None or invoked.re_executable
                if error.retryable and not capability_permits_retry:
                    recorder.record(
                        "retry_withheld",
                        tool=tool_name,
                        attempt=attempt,
                        reason="capability_not_re_executable",
                    )

                # BUDGET. Every part of this condition is controller state:
                # `retryable` comes from the controller's own code table,
                # `attempt`/`max_attempts` from the frozen RunContext, and
                # `re_executable` from the immutable ToolSpec. No value the
                # model produced participates in this decision.
                if (
                    error.retryable
                    and capability_permits_retry
                    and attempt < run_context.max_attempts
                ):
                    self._enter(machine, recorder, State.RETRY)
                    recorder.record("retry", attempt=attempt, next_attempt=attempt + 1)
                    feedback = ToolFeedback(tool=tool_name, accepted=False, error=error)
                    attempt += 1
                    self._enter(machine, recorder, State.GENERATE)
                    continue

                # A retry withheld by the capability gate still reports
                # RETRY_EXHAUSTED to the model: from the model's side no
                # further attempt is available, which is exactly what that code
                # means, and telling it *why* would leak the capability's
                # side-effect classification into a channel that must not carry
                # it. The true reason is in the audit stream above.
                terminal_code: ErrorCode = "RETRY_EXHAUSTED" if error.retryable else error.code
                self._enter(machine, recorder, State.TERMINAL)
                recorder.record("terminal", status="failed", code=terminal_code, attempts=attempt)
                self._persist(
                    RunTerminal(
                        run_id=run_context.run_id,
                        status="failed",
                        code=terminal_code,
                        attempts=attempt,
                    )
                )
                return RunOutcome(
                    terminal=ControllerTerminal(
                        status="failed", code=terminal_code, attempts=attempt
                    ),
                    states=tuple(machine.history),
                    events=recorder.snapshot(),
                    attempts=attempt,
                    error=last_error,
                )

            self._enter(machine, recorder, State.RESPOND)
            executions_completed += 1
            last_result = result
            last_execution_attempts = attempt
            recorder.record("execution_finished", step=step_id, executions=executions_completed)

            if not resumed_run:
                # COMPOSITION BOUNDARY (Milestone 10). One execution has
                # finished; ask whether another is wanted. The controller does
                # NOT decide here that the run is over, and it does not decide
                # that another execution happens either — it asks, and the
                # model's next answer takes one of the three branches at PARSE:
                # a proposal (continue), an `ExecutionComplete` (terminate
                # successfully), or anything else (the unchanged fail-closed
                # path).
                #
                # The ceiling is deliberately NOT consulted here. Stopping
                # early because capacity is gone would report a truncated run
                # as complete, conflating "the ceiling was reached" with "the
                # task is finished" — the silent truncation this milestone
                # exists to prevent. So the question is always asked, and a
                # proposal beyond the ceiling is refused loudly above.
                execution_index += 1
                step_id = f"{run_context.run_id}-s{execution_index}"
                attempt = 1
                feedback = None
                self._enter(machine, recorder, State.GENERATE)
                continue

            # A resumed run stops here, preserving the Milestone 6 contract.
            self._enter(machine, recorder, State.TERMINAL)
            recorder.record("terminal", status="succeeded", attempts=attempt)
            self._persist(
                RunTerminal(run_id=run_context.run_id, status="succeeded", attempts=attempt)
            )
            return RunOutcome(
                terminal=ControllerTerminal(status="succeeded", code=None, attempts=attempt),
                states=tuple(machine.history),
                events=recorder.snapshot(),
                attempts=attempt,
                result=result,
                executions=executions_completed,
            )

    # -- individual gates -------------------------------------------------

    def _persist(self, record: DurableRecord) -> None:
        """Durably record one controller fact, when this run has a journal.

        A no-op without one. Persistence is something a run is wired with, not
        a dependency the controller cannot operate without.
        """
        if self._journal is not None:
            self._journal.append(record)

    # -- operator-controlled recovery (Milestone 6) -----------------------

    async def recover(
        self,
        run_context: RunContext,
        decision: OperatorDecision,
        messages: Sequence[dict[str, str]] = (),
    ) -> RecoveryOutcome:
        """Act on one explicit operator decision about one crashed run.

        The order of operations is the security property, so it is worth
        stating plainly:

        1. the controller derives the plan from the journal — the operator
           never supplies one;
        2. the decision is bound to that exact plan, or refused, with nothing
           persisted and nothing executed;
        3. the decision is persisted durably, *before* anything acts on it;
        4. **everything is re-validated from scratch**, against a freshly
           re-read journal and the live registry, `RunContext` and gates;
        5. only then does the ordinary execution path run — the same
           `_loop` a fresh run uses, with the same gates in the same order.

        Step 4 is not redundant with step 2. An approval is a statement about a
        moment, and the moment ends the instant the decision is recorded: the
        registry may have changed, the run's grants may have narrowed, the
        journal may have grown. The controller therefore trusts the approval
        for exactly one thing — that a human said yes to this plan — and
        re-establishes every other fact for itself.

        `messages` is supplied by the caller because the journal deliberately
        never stored the conversation. A resume that succeeds does not use it;
        a resume whose execution fails and still has budget continues into an
        ordinary retry, which does need something to send.
        """
        if self._journal is None:
            # Recovery is about durable state. Without a journal there is
            # nothing to recover from, and inventing a plan from memory would
            # be the controller trusting itself instead of its evidence.
            raise RecoveryRefused("recovery_requires_a_journal")

        recorder = EventRecorder(run_context.run_id)
        plan = plan_recovery(self._journal.records(), self._registry, run_context)
        recorder.record(
            "recovery_planned",
            disposition=plan.disposition,
            plan_id=plan.plan_id,
            actions=len(plan.available_actions),
        )

        # Binding. Raises OperatorDecisionRejected, having persisted nothing.
        validate_decision(decision, plan)

        self._persist(
            OperatorDecisionRecorded(
                run_id=run_context.run_id,
                decision_sequence=decision.decision_sequence,
                action=decision.action,
                plan_id=decision.plan_id,
                expected_execution_id=decision.expected_execution_id,
                reason_code=decision.reason_code,
            )
        )
        recorder.record(
            "operator_decision_recorded",
            action=decision.action,
            decision_sequence=decision.decision_sequence,
            reason=decision.reason_code,
        )

        seed = self._revalidate_recovery(run_context, plan, decision, recorder)

        if decision.action == "resume":
            assert seed is not None  # _revalidate_recovery guarantees it
            machine = Run()
            recorder.record("state_entered", state=State.RECEIVE.value)
            self._enter(machine, recorder, State.CLASSIFY)
            self._enter(machine, recorder, State.GENERATE)
            outcome = await self._loop(run_context, messages, machine, recorder, seed=seed)
            return RecoveryOutcome(
                run_id=run_context.run_id,
                action=decision.action,
                plan_id=plan.plan_id,
                decision_sequence=decision.decision_sequence,
                disposition=plan.disposition,
                reason_code=plan.reason_code,
                resulting_state=State.TERMINAL.value,
                terminal=True,
                terminal_status=outcome.terminal.status,
                executed=True,
                execution_id=plan.execution_id,
                run=outcome,
            )

        if decision.action in ("abort", "terminalize"):
            # No executor, no model, no retry, and no fabricated result. An
            # abort is a controller decision to stop; it is emphatically not a
            # tool failure, and nothing here synthesises one.
            status = "aborted" if decision.action == "abort" else "failed"
            code = "OPERATOR_ABORT" if decision.action == "abort" else "OPERATOR_TERMINALIZED"
            self._persist(
                RunTerminal(
                    run_id=run_context.run_id,
                    status=status,
                    code=code,
                    attempts=plan.attempt or 1,
                )
            )
            recorder.record("recovery_terminalized", action=decision.action, status=status)
            recorder.record("terminal", status=status, code=code, attempts=plan.attempt or 1)
            return RecoveryOutcome(
                run_id=run_context.run_id,
                action=decision.action,
                plan_id=plan.plan_id,
                decision_sequence=decision.decision_sequence,
                disposition=plan.disposition,
                reason_code=plan.reason_code,
                resulting_state=State.TERMINAL.value,
                terminal=True,
                terminal_status=status,
                executed=False,
                execution_id=plan.execution_id,
            )

        # `acknowledge` and `reject_recovery`. The decision is recorded and the
        # run is left exactly as it was: not executed, not terminal, and — via
        # the new decision changing the plan's identity — needing a fresh plan
        # and a fresh decision before anything can happen.
        recorder.record("recovery_declined", action=decision.action)
        return RecoveryOutcome(
            run_id=run_context.run_id,
            action=decision.action,
            plan_id=plan.plan_id,
            decision_sequence=decision.decision_sequence,
            disposition=plan.disposition,
            reason_code=plan.reason_code,
            resulting_state=plan.disposition,
            terminal=False,
            executed=False,
            execution_id=plan.execution_id,
        )

    def _revalidate_recovery(
        self,
        run_context: RunContext,
        plan: RecoveryPlan,
        decision: OperatorDecision,
        recorder: EventRecorder,
    ) -> _ResumeSeed | None:
        """Re-establish every fact from scratch, after the decision is durable.

        Two halves. The first re-reads the journal and re-derives the plan,
        proving that the world the operator approved is still the world that
        exists — and that the decision was recorded exactly once. The second
        runs only for `resume`, and re-resolves the tool, re-validates the
        arguments against its *current* schema, re-runs both gates, and
        re-derives the execution identity, so nothing reaches the executor on
        an assumption carried over from before.
        """
        assert self._journal is not None  # caller checked
        fresh = plan_recovery(self._journal.records(), self._registry, run_context)

        if fresh.run_id != run_context.run_id:
            raise RecoveryRefused("run_id_changed")
        if fresh.is_terminal:
            raise RecoveryRefused("run_became_terminal")
        if fresh.max_attempts != plan.max_attempts:
            raise RecoveryRefused("retry_budget_changed")
        if fresh.disposition != plan.disposition:
            raise RecoveryRefused("disposition_changed")
        if fresh.execution_id != plan.execution_id:
            raise RecoveryRefused("execution_identity_changed")
        if fresh.tool != plan.tool:
            raise RecoveryRefused("tool_changed")
        if fresh.arguments != plan.arguments:
            raise RecoveryRefused("arguments_changed")
        if fresh.attempt != plan.attempt or fresh.step_id != plan.step_id:
            raise RecoveryRefused("execution_position_changed")
        if fresh.side_effect_free != plan.side_effect_free:
            raise RecoveryRefused("side_effect_flag_changed")
        if fresh.decisions_recorded != plan.decisions_recorded + 1:
            # Exactly one decision was added: this one. More would mean a
            # concurrent writer; fewer would mean the write did not land.
            raise RecoveryRefused("decision_not_recorded_exactly_once")
        if fresh.last_action != decision.action:
            raise RecoveryRefused("recorded_decision_mismatch")

        recorder.record("recovery_revalidated", action=decision.action, plan_id=plan.plan_id)

        if decision.action != "resume":
            return None

        if not fresh.authorization_valid:
            raise RecoveryRefused("authorization_no_longer_valid")

        assert fresh.tool is not None
        assert fresh.arguments is not None
        assert fresh.step_id is not None
        assert fresh.attempt is not None
        assert fresh.execution_id is not None

        spec = self._registry.get(fresh.tool)
        if spec is None:
            raise RecoveryRefused("tool_not_in_registry")
        if spec.side_effect_free != fresh.side_effect_free:
            raise RecoveryRefused("side_effect_flag_changed")

        try:
            args = spec.args_schema.model_validate(fresh.arguments)
        except ValidationError as exc:
            raise RecoveryRefused("arguments_no_longer_valid") from exc

        if not authorize(spec, args, run_context).allowed:
            raise RecoveryRefused("authorization_denied")
        if not evaluate_policy(spec, args, run_context).allowed:
            raise RecoveryRefused("policy_denied")

        # The identity must still be a function of the operation being
        # resumed. If it is not, something between the journal and here
        # disagrees, and the safe reading is that this is not the same
        # execution the operator approved.
        rederived = derive_execution_id(
            run_context.run_id,
            fresh.step_id,
            fresh.attempt,
            spec.name,
            args.model_dump(mode="json"),
        )
        if rederived != fresh.execution_id:
            raise RecoveryRefused("execution_identity_mismatch")
        if decision.expected_execution_id != rederived:
            raise RecoveryRefused("execution_identity_mismatch")

        return _ResumeSeed(
            spec=spec,
            args=args,
            step_id=fresh.step_id,
            attempt=fresh.attempt,
            execution_id=rederived,
        )

    def _persist_authorization(self, record: DurableRecord, recorder: EventRecorder) -> None:
        """Write the write-ahead record, or refuse the attempt cleanly.

        Every other durable write in this class may propagate a `JournalError`,
        because at those points either nothing is pending or the physical call
        has already happened and a loud failure is the honest outcome. This one
        is different: it sits immediately before the executor, so a raised
        error here means *nothing ran*, and the correct outcome is a refusal
        rather than an exception escaping `run()`.

        Milestone 8 made this reachable. Arguments are persisted, and a write
        capability's `content` is the first argument large enough to approach
        `records.MAX_ARGUMENTS_BYTES` — worst-case JSON escaping inflates a
        payload six-fold, so a content field inside the capability's own
        ceiling can still exceed the record ceiling. Measured on the Milestone 7
        tree, that propagated out of `run()` as an unhandled `JournalError`.

        The refusal is `POLICY_DENIED`: non-retryable, because the same
        arguments would fail identically, and opaque, because which ceiling was
        hit is controller-internal. The real reason goes to the audit stream.
        """
        try:
            self._persist(record)
        except JournalError as exc:
            recorder.record("authorization_not_persistable", reason=exc.reason)
            raise _Rejection("POLICY_DENIED", _DENIED_MESSAGE) from exc

    def _enter(self, machine: Run, recorder: EventRecorder, state: State) -> None:
        machine.advance(state)
        recorder.record("state_entered", state=state.value)

    def _validate(
        self, candidate: RawToolCall, recorder: EventRecorder
    ) -> tuple[ToolSpec, BaseModel]:
        """Resolve the tool name against the registry, then type its arguments."""
        spec = self._registry.get(candidate.tool)
        if spec is None:
            # Unknown names stop here: there is no executor to reach.
            recorder.record("tool_not_found", tool=candidate.tool)
            raise _Rejection("TOOL_NOT_FOUND", _UNKNOWN_TOOL_MESSAGE)

        try:
            args = spec.args_schema.model_validate(candidate.arguments)
        except ValidationError as exc:
            field_errors = _sanitize_validation_errors(exc)
            recorder.record("schema_rejected", tool=spec.name, field_error_count=len(field_errors))
            raise _Rejection("SCHEMA_INVALID", _SCHEMA_MESSAGE, field_errors) from exc

        return spec, args

    def _authorize(
        self,
        spec: ToolSpec,
        args: BaseModel,
        run_context: RunContext,
        recorder: EventRecorder,
    ) -> None:
        decision = authorize(spec, args, run_context)
        if not decision.allowed:
            # `reason` is audit-only. The model gets the generic denial.
            recorder.record("authorization_rejected", tool=spec.name, reason=decision.reason)
            raise _Rejection("POLICY_DENIED", _DENIED_MESSAGE)

    def _policy(
        self,
        spec: ToolSpec,
        args: BaseModel,
        run_context: RunContext,
        recorder: EventRecorder,
    ) -> None:
        decision = evaluate_policy(spec, args, run_context)
        if not decision.allowed:
            recorder.record("policy_rejected", tool=spec.name, reason=decision.reason)
            raise _Rejection("POLICY_DENIED", _DENIED_MESSAGE)

    def _execute(
        self,
        spec: ToolSpec,
        args: BaseModel,
        tool_call_id: str,
        attempt: int,
        recorder: EventRecorder,
    ) -> Any:
        recorder.record(
            "execution_started",
            tool=spec.name,
            tool_call_id=tool_call_id,
            attempt=attempt,
            timeout_seconds=int(spec.timeout_seconds),
        )
        try:
            return spec.executor.execute(args)
        except TimeoutError as exc:
            # Normalized, not propagated. The exception's own text is dropped.
            recorder.record("execution_failed", tool=spec.name, code="EXECUTION_TIMEOUT")
            raise _Rejection("EXECUTION_TIMEOUT", _TIMEOUT_MESSAGE) from exc
        except ToolDenialError as exc:
            # An authorization fact the executor could only establish by
            # resolving the resource. Same code, same message, and the same
            # non-retryable disposition as the AUTHORIZE and POLICY_CHECK
            # gates — retrying a denial is just asking twice.
            recorder.record("policy_rejected", tool=spec.name, reason=exc.reason)
            raise _Rejection("POLICY_DENIED", _DENIED_MESSAGE) from exc
        except ToolExecutionError as exc:
            recorder.record(
                "execution_failed",
                tool=spec.name,
                code="EXECUTION_FAILED",
                reason=exc.reason,
            )
            raise _Rejection("EXECUTION_FAILED", _EXECUTION_MESSAGE) from exc
        # Any other exception is a programmer error and propagates on purpose
        # (spec §"error_handling"): a blanket `except Exception` here would
        # hide real defects behind a normalized error code.

    def _verify(self, spec: ToolSpec, raw_result: Any, recorder: EventRecorder) -> BaseModel:
        """Type the executor's return value before anyone treats it as a result.

        A corrupt or unexpected shape becomes VERIFICATION_FAILED. Note what
        this method does *not* do: it never inspects the result's contents for
        instructions, and nothing downstream re-reads them as control input.
        Tool output is data (spec §"tool_result_boundary").
        """
        try:
            result = spec.result_schema.model_validate(raw_result)
        except ValidationError as exc:
            recorder.record("verification_failed", tool=spec.name)
            raise _Rejection("VERIFICATION_FAILED", _VERIFICATION_MESSAGE) from exc

        if getattr(result, "status", None) == "error":
            recorder.record("execution_failed", tool=spec.name, code="EXECUTION_FAILED")
            raise _Rejection("EXECUTION_FAILED", _EXECUTION_MESSAGE)

        data = getattr(result, "data", None)
        recorder.record(
            "execution_succeeded",
            tool=spec.name,
            result_count=len(data) if isinstance(data, list) else 0,
        )
        return result
