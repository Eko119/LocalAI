"""State machine tests: the transition table is the whole contract.

The key test here is exhaustive rather than illustrative — it walks the
complete State x State product and asserts that every pair absent from
`TRANSITIONS` raises. That is what "every illegal transition must fail
deterministically" means operationally: not "the ones we thought of".
"""

from __future__ import annotations

import itertools

import pytest

from local_agent.state_machine import (
    TRANSITIONS,
    IllegalStateTransitionError,
    Run,
    State,
)


def test_every_state_has_an_entry_in_the_table() -> None:
    assert set(TRANSITIONS) == set(State)


def test_terminal_has_no_outgoing_edges() -> None:
    assert TRANSITIONS[State.TERMINAL] == frozenset()


def test_execution_is_unreachable_without_passing_every_gate() -> None:
    """The only edge into EXECUTE comes from POLICY_CHECK."""
    predecessors = {source for source, targets in TRANSITIONS.items() if State.EXECUTE in targets}
    assert predecessors == {State.POLICY_CHECK}


def test_policy_check_is_only_reachable_from_authorize() -> None:
    predecessors = {
        source for source, targets in TRANSITIONS.items() if State.POLICY_CHECK in targets
    }
    assert predecessors == {State.AUTHORIZE}


def test_authorize_is_only_reachable_from_validate() -> None:
    predecessors = {source for source, targets in TRANSITIONS.items() if State.AUTHORIZE in targets}
    assert predecessors == {State.VALIDATE}


@pytest.mark.parametrize(("source", "target"), list(itertools.product(State, State)))
def test_exhaustive_transition_legality(source: State, target: State) -> None:
    """Walk all 169 ordered pairs; legality must match the table exactly."""
    machine = Run()
    machine.state = source
    machine.history = [source]

    if target in TRANSITIONS[source]:
        machine.advance(target)
        assert machine.state is target
        assert machine.history == [source, target]
    else:
        with pytest.raises(IllegalStateTransitionError) as excinfo:
            machine.advance(target)
        assert excinfo.value.current is source
        assert excinfo.value.attempted is target
        # A rejected transition leaves the machine exactly where it was.
        assert machine.state is source
        assert machine.history == [source]


def test_no_state_can_self_loop() -> None:
    for state in State:
        assert state not in TRANSITIONS[state]


def test_history_records_the_full_trace() -> None:
    machine = Run()
    for state in (State.CLASSIFY, State.GENERATE, State.PARSE, State.VALIDATE):
        machine.advance(state)

    assert machine.history == [
        State.RECEIVE,
        State.CLASSIFY,
        State.GENERATE,
        State.PARSE,
        State.VALIDATE,
    ]
    assert machine.is_terminal is False
