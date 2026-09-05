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
