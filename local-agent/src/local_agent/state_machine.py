"""Explicit deterministic state machine for the controller.

Every legal transition is enumerated in `TRANSITIONS`. Every other transition
is illegal and raises `IllegalStateTransitionError`. This is the mechanism
that makes "the model cannot invent states" and "terminal states cannot
return to execution" checkable, not just documented: `Run.advance()` is the
single choke point every state change passes through, and it consults this
table rather than trusting caller-supplied control flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, unique


@unique
class State(Enum):
    """The fixed state graph (spec 03-agent-architecture.md §2, contract §"state_machine").

    The model never sees this enum and has no way to construct a `State`
    value that isn't one of these members — there is no free-text or
    model-suppliable state field anywhere in the request/response contracts.
    """

    RECEIVE = "RECEIVE"
    CLASSIFY = "CLASSIFY"
    GENERATE = "GENERATE"
    PARSE = "PARSE"
    VALIDATE = "VALIDATE"
    AUTHORIZE = "AUTHORIZE"
    POLICY_CHECK = "POLICY_CHECK"
    EXECUTE = "EXECUTE"
    VERIFY = "VERIFY"
    RESPOND = "RESPOND"
    FEEDBACK = "FEEDBACK"
    RETRY = "RETRY"
    TERMINAL = "TERMINAL"


# The explicit transition table. Keys are the "from" state; values are the
# set of "to" states legally reachable from it in one step.
#
#   RECEIVE -> CLASSIFY -> GENERATE -> PARSE -> VALIDATE -> AUTHORIZE
#   -> POLICY_CHECK -> EXECUTE -> VERIFY -> RESPOND -> TERMINAL
#
# GENERATE reaches FEEDBACK only when the model call itself failed — the
# service timed out, was unreachable, or answered unusably — so there is no
# generation to parse. EXECUTE reaches FEEDBACK only when the executor raised
# and so produced no result to verify; a completed execution always goes
# through VERIFY.
# Any rejection at GENERATE/PARSE/VALIDATE/AUTHORIZE/POLICY_CHECK/EXECUTE/VERIFY routes to
# FEEDBACK, which then either loops back to GENERATE via RETRY (budget
# remaining) or ends the run at TERMINAL (exhausted or non-retryable).
# TERMINAL has no outgoing edges: once entered, a run is over.
#
# Milestone 10 adds exactly two edges, and only two:
#
#   RESPOND -> GENERATE   a successful execution may be followed by another,
#                         when the model asks for one and the run's
#                         `max_executions` ceiling still has capacity. This is
#                         NOT unconditional: the controller asks, and the
#                         model's next answer decides which branch is taken.
#   PARSE   -> TERMINAL   the model answered with `ExecutionComplete` — an
#                         affirmative "no further execution is required".
#                         Absence of a proposal is still TOOL_CALL_MALFORMED
#                         and still routes to FEEDBACK, unchanged.
#
# Together they turn the attempt loop into an attempt loop nested inside an
# execution loop, without a second state machine to manage the sequence.
TRANSITIONS: dict[State, frozenset[State]] = {
    State.RECEIVE: frozenset({State.CLASSIFY}),
    State.CLASSIFY: frozenset({State.GENERATE}),
    State.GENERATE: frozenset({State.PARSE, State.FEEDBACK}),
    State.PARSE: frozenset({State.VALIDATE, State.FEEDBACK, State.TERMINAL}),
    State.VALIDATE: frozenset({State.AUTHORIZE, State.FEEDBACK}),
    State.AUTHORIZE: frozenset({State.POLICY_CHECK, State.FEEDBACK}),
    State.POLICY_CHECK: frozenset({State.EXECUTE, State.FEEDBACK}),
    State.EXECUTE: frozenset({State.VERIFY, State.FEEDBACK}),
    State.VERIFY: frozenset({State.RESPOND, State.FEEDBACK}),
    State.RESPOND: frozenset({State.TERMINAL, State.GENERATE}),
    State.FEEDBACK: frozenset({State.RETRY, State.TERMINAL}),
    State.RETRY: frozenset({State.GENERATE}),
    State.TERMINAL: frozenset(),
}


class IllegalStateTransitionError(RuntimeError):
    """Raised when code attempts a transition absent from `TRANSITIONS`."""

    def __init__(self, current: State, attempted: State) -> None:
        self.current = current
        self.attempted = attempted
        super().__init__(
            f"illegal state transition: {current.value} -> {attempted.value} "
            f"(legal targets: {sorted(s.value for s in TRANSITIONS[current])})"
        )


@dataclass
class Run:
    """Tracks the live state of one controller run and enforces the table.

    `history` is the ordered trace of states entered — the thing the
    deterministic-replay test compares across repeated executions.
    """

    state: State = State.RECEIVE
    history: list[State] = field(default_factory=lambda: [State.RECEIVE])

    def advance(self, to: State) -> None:
        """Move to `to` if legal, else raise. This is the only way to change `state`."""
        legal = TRANSITIONS[self.state]
        if to not in legal:
            raise IllegalStateTransitionError(self.state, to)
        self.state = to
        self.history.append(to)

    @property
    def is_terminal(self) -> bool:
        return self.state is State.TERMINAL
