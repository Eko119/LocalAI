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
    RETRYABLE_CODES,
    ControllerError,
    ControllerTerminal,
    ErrorCode,
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
from .policy import RunContext, authorize, evaluate_policy
from .registry import ToolDenialError, ToolExecutionError, ToolRegistry, ToolSpec
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


def parse_candidate(response: ModelResponse) -> RawToolCall:
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


@dataclass(frozen=True)
class RunOutcome:
    """Everything a caller (or a test) needs to audit one run."""

    terminal: ControllerTerminal
    states: tuple[State, ...]
    events: tuple[Event, ...]
    attempts: int
    result: BaseModel | None = None
    error: ControllerError | None = None

    @property
    def succeeded(self) -> bool:
        return self.terminal.status == "succeeded"


class Controller:
    """Owns the run. Constructed by trusted wiring, never by model output."""

    def __init__(self, registry: ToolRegistry, adapter: ModelAdapter) -> None:
        self._registry = registry
        self._adapter = adapter

    async def run(
        self,
        run_context: RunContext,
        messages: Sequence[dict[str, str]],
    ) -> RunOutcome:
        recorder = EventRecorder(run_context.run_id)
        machine = Run()
        recorder.record("run_created", max_attempts=run_context.max_attempts)
        recorder.record("state_entered", state=State.RECEIVE.value)

        self._enter(machine, recorder, State.CLASSIFY)
        self._enter(machine, recorder, State.GENERATE)

        step_id = f"{run_context.run_id}-s1"
        attempt = 1
        feedback: ToolFeedback | None = None
        last_error: ControllerError | None = None

        while True:
            tool_call_id = f"{step_id}-a{attempt}"
            tool_name = "unknown"

            try:
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
                # Any other exception from an adapter is a programmer error and
                # propagates on purpose, exactly as it does for an executor.

                recorder.record(
                    "model_output_received",
                    attempt=attempt,
                    # Structural facts only — never the generated text itself.
                    has_structured_output=response.structured_output is not None,
                    has_reasoning=response.reasoning is not None,
                )

                self._enter(machine, recorder, State.PARSE)
                candidate = parse_candidate(response)
                tool_name = candidate.tool
                recorder.record("candidate_parsed", tool=tool_name, attempt=attempt)

                self._enter(machine, recorder, State.VALIDATE)
                spec, args = self._validate(candidate, recorder)

                self._enter(machine, recorder, State.AUTHORIZE)
                self._authorize(spec, args, run_context, recorder)

                self._enter(machine, recorder, State.POLICY_CHECK)
                self._policy(spec, args, run_context, recorder)

                self._enter(machine, recorder, State.EXECUTE)
                raw_result = self._execute(spec, args, tool_call_id, attempt, recorder)

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

                # BUDGET. Both halves of this condition are controller state:
                # `retryable` comes from the controller's own code table and
                # `attempt`/`max_attempts` from the frozen RunContext. No value
                # the model produced participates in this decision.
                if error.retryable and attempt < run_context.max_attempts:
                    self._enter(machine, recorder, State.RETRY)
                    recorder.record("retry", attempt=attempt, next_attempt=attempt + 1)
                    feedback = ToolFeedback(tool=tool_name, accepted=False, error=error)
                    attempt += 1
                    self._enter(machine, recorder, State.GENERATE)
                    continue

                terminal_code: ErrorCode = "RETRY_EXHAUSTED" if error.retryable else error.code
                self._enter(machine, recorder, State.TERMINAL)
                recorder.record("terminal", status="failed", code=terminal_code, attempts=attempt)
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
            self._enter(machine, recorder, State.TERMINAL)
            recorder.record("terminal", status="succeeded", attempts=attempt)
            return RunOutcome(
                terminal=ControllerTerminal(status="succeeded", code=None, attempts=attempt),
                states=tuple(machine.history),
                events=recorder.snapshot(),
                attempts=attempt,
                result=result,
            )

    # -- individual gates -------------------------------------------------

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
