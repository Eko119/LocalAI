"""Structured, deterministic audit events.

Two rules shape this module:

1. **No secrets, no payloads.** Events record *structural* facts — which
   state was entered, which tool was proposed, which error code was
   emitted, which internal reason a gate denied for. They never carry raw
   model text, tool result contents, argument values, or tracebacks. That
   keeps the audit stream safe to log or persist wholesale and means an
   injection attempt inside a query string or a tool result never reaches
   the log as executable-looking text.

2. **No wall clock, no randomness.** Ordering comes from a monotonic
   sequence number assigned by the recorder, not `time.time()`. Timestamps
   would make the event trace differ between otherwise identical runs and
   would break the deterministic-replay guarantee this milestone exists to
   prove. Real-time correlation is a persistence concern (deferred).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

EventType = Literal[
    "run_created",
    "state_entered",
    "model_output_received",
    "model_call_failed",
    "candidate_parsed",
    "schema_rejected",
    "tool_not_found",
    "authorization_rejected",
    "policy_rejected",
    "execution_started",
    "execution_succeeded",
    "execution_failed",
    "verification_failed",
    "retry",
    # Milestone 7: a retry the budget allowed but the capability contract did
    # not, because re-running it would compound a side effect.
    "retry_withheld",
    # Milestone 8: the write-ahead record could not be persisted, so the
    # attempt was refused before the executor rather than crashing the run.
    "authorization_not_persistable",
    # Milestone 10: composition. Structural facts only, as everywhere else —
    # a step id, two counts and a ceiling. Never a payload, never model text.
    #
    # `execution_finished` marks one execution's boundary, which is what makes
    # a composed run auditable as a sequence rather than as one blur.
    "execution_finished",
    # The model affirmatively declared that no further execution is required.
    # Distinct from any failure code: this is a success path, and it exists so
    # that completion is never inferred from absence.
    "execution_complete_declared",
    # A further execution was requested with the run's composition ceiling
    # already consumed. Refused before authorization, so nothing reached the
    # executor, and non-retryable, so no attempt counter moved.
    "execution_ceiling_exhausted",
    # A completion arrived while a rejection was outstanding. Refused: the
    # model was asked to repair a proposal, and "I am finished" is not a
    # repair. Without this a refusal could be laundered into a success.
    "completion_rejected_during_repair",
    # Milestone 6: the operator control plane. Structural facts only, as
    # everywhere else — an action name, a plan id, a sequence, a stable reason
    # code. Never an operator identity, never free text.
    "recovery_planned",
    "operator_decision_recorded",
    "recovery_revalidated",
    "recovery_resumed",
    "recovery_terminalized",
    "recovery_declined",
    "terminal",
]


@dataclass(frozen=True)
class Event:
    """One immutable audit record."""

    seq: int
    run_id: str
    type: EventType
    detail: tuple[tuple[str, str | int | bool], ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "seq": self.seq,
            "run_id": self.run_id,
            "type": self.type,
            "detail": dict(self.detail),
        }


@dataclass
class EventRecorder:
    """Append-only event sink for a single run."""

    run_id: str
    events: list[Event] = field(default_factory=list)

    def record(self, type_: EventType, **detail: str | int | bool) -> None:
        # Sorted so the serialized trace is stable regardless of kwarg order.
        payload = tuple(sorted(detail.items()))
        self.events.append(Event(len(self.events), self.run_id, type_, payload))

    def types(self) -> tuple[EventType, ...]:
        return tuple(e.type for e in self.events)

    def snapshot(self) -> tuple[Event, ...]:
        return tuple(self.events)
