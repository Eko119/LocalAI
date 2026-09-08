"""The 20 required adversarial cases (task §"adversarial_tests", spec 09).

Every rejection test asserts two things, per the contract: the correct
rejection outcome, *and* that the executor was never invoked. The executor
spy (`harness.executor.call_count`) is what makes the second assertion real
rather than assumed.

Case numbering matches the task list so the mapping is auditable.
"""

from __future__ import annotations

import json

import pytest
from conftest import (
    CorruptResultExecutor,
    FailingExecutor,
    InjectingExecutor,
    build_harness,
    call_with_arguments,
    tool_call_json,
    valid_call,
)

from local_agent.contracts import ModelResponse
from local_agent.policy import RunContext
from local_agent.state_machine import State


def _resp(structured: str | None = None, **kw: str | None) -> ModelResponse:
    return ModelResponse(structured_output=structured, **kw)


# --- 1. valid tool call ---------------------------------------------------


def test_case_01_valid_tool_call_executes() -> None:
    harness = build_harness(_resp(valid_call()))
    outcome = harness.run()

    assert outcome.succeeded
    assert outcome.terminal.attempts == 1
    assert outcome.result is not None
    assert outcome.result.model_dump() == {
        "status": "success",
        "data": ["clutch_replacement.md"],
    }
    assert harness.executor.call_count == 1
    assert [s for s in outcome.states] == [
        State.RECEIVE,
        State.CLASSIFY,
        State.GENERATE,
        State.PARSE,
        State.VALIDATE,
        State.AUTHORIZE,
        State.POLICY_CHECK,
        State.EXECUTE,
        State.VERIFY,
        State.RESPOND,
        # Milestone 10: a successful execution is followed by asking whether
        # another is wanted. The model answered with an affirmative completion,
        # which is parsed and ends the run — so the shape gains one more
        # GENERATE/PARSE pair rather than terminating straight from RESPOND.
        State.GENERATE,
        State.PARSE,
        State.TERMINAL,
    ]


# --- 2-6. schema violations ----------------------------------------------
# All of these are rejected by the declared schema, not by any per-case
# branch in the controller: the controller only ever calls
# `spec.args_schema.model_validate`.


@pytest.mark.parametrize(
    ("label", "arguments", "expected_field"),
    [
        ("02_missing_query", {"root_id": "workspace"}, "query"),
        ("03_empty_query", {"query": "", "root_id": "workspace"}, "query"),
        ("04_oversized_query", {"query": "x" * 501, "root_id": "workspace"}, "query"),
        (
            "05_max_results_zero",
            {"query": "notes", "root_id": "workspace", "max_results": 0},
            "max_results",
        ),
        (
            "06_max_results_5000",
            {"query": "notes", "root_id": "workspace", "max_results": 5000},
            "max_results",
        ),
    ],
)
def test_cases_02_to_06_schema_violations_never_execute(
    label: str, arguments: dict[str, object], expected_field: str
) -> None:
    harness = build_harness(_resp(call_with_arguments(arguments)), complete=False)
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "SCHEMA_INVALID"
    assert outcome.error.retryable is True
    assert expected_field in {fe["field"] for fe in outcome.error.field_errors}
    # Retryable, so the budget is spent and the run ends terminally.
    assert outcome.terminal.status == "failed"
    assert outcome.terminal.code == "RETRY_EXHAUSTED"
    assert outcome.terminal.attempts == 3
    assert harness.executor.call_count == 0


def test_case_04_oversized_query_is_not_echoed_back_to_the_model() -> None:
    """Feedback must be actionable without echoing the model's own payload."""
    harness = build_harness(_resp(tool_call_json(query="x" * 501, root_id="workspace")))
    outcome = harness.run()

    serialized = json.dumps(outcome.error.model_dump() if outcome.error else {})
    assert "x" * 100 not in serialized
    assert "500" in serialized  # the constraint itself is disclosed, so it can be fixed


# --- 7. unknown tool ------------------------------------------------------


def test_case_07_unknown_tool_is_terminal_and_never_reaches_an_executor() -> None:
    harness = build_harness(_resp(tool_call_json(tool="shell_exec", command="rm -rf /")))
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "TOOL_NOT_FOUND"
    assert outcome.error.retryable is False
    assert outcome.terminal.code == "TOOL_NOT_FOUND"
    assert outcome.terminal.attempts == 1  # non-retryable: no second attempt
    assert harness.executor.call_count == 0
    assert harness.adapter.call_count == 1
    assert State.EXECUTE not in outcome.states


# --- 8. unauthorized root -------------------------------------------------


def test_case_08_unauthorized_root_denied_at_the_authorization_gate() -> None:
    """`workspace` is schema-legal, but this run only holds the `knowledge` grant.

    This is the case that proves authorization is a separate gate from the
    schema: the arguments validate cleanly and are still denied.
    """
    context = RunContext(run_id="run-auth", authorized_roots=frozenset({"knowledge"}))
    harness = build_harness(_resp(valid_call(root_id="workspace")), run_context=context)
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "POLICY_DENIED"
    assert outcome.error.retryable is False
    assert outcome.terminal.code == "POLICY_DENIED"
    assert harness.executor.call_count == 0
    assert State.AUTHORIZE in outcome.states
    assert State.POLICY_CHECK not in outcome.states  # denied before policy ran
    assert State.EXECUTE not in outcome.states


def test_case_08b_policy_gate_denies_a_fully_authorized_request() -> None:
    """Authorization granted, policy still says no — the two gates are independent."""
    context = RunContext(run_id="run-policy", max_results_ceiling=5)
    harness = build_harness(_resp(valid_call(max_results=10)), run_context=context)
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "POLICY_DENIED"
    assert State.AUTHORIZE in outcome.states  # authorization passed
    assert State.POLICY_CHECK in outcome.states  # policy is where it stopped
    assert State.EXECUTE not in outcome.states
    assert harness.executor.call_count == 0


# --- 9. arbitrary filesystem path ----------------------------------------


@pytest.mark.parametrize(
    "root",
    ["/etc/passwd", "../../etc/shadow", "C:\\Windows\\System32", "workspace/../secrets"],
)
def test_case_09_arbitrary_paths_cannot_substitute_for_a_root_id(root: str) -> None:
    harness = build_harness(_resp(valid_call(root_id=root)))
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "SCHEMA_INVALID"
    assert "root_id" in {fe["field"] for fe in outcome.error.field_errors}
    assert harness.executor.call_count == 0
    assert State.EXECUTE not in outcome.states


# --- 10. raw shell injection ---------------------------------------------


def test_case_10_raw_shell_text_on_the_structured_channel_is_malformed() -> None:
    harness = build_harness(_resp("rm -rf / --no-preserve-root"))
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "TOOL_CALL_MALFORMED"
    assert harness.executor.call_count == 0


def test_case_10b_shell_text_inside_a_valid_argument_is_only_ever_a_string() -> None:
    """The general defence: there is no shell tool to route it to.

    `rm -rf /` as a *query* is a search string. It reaches the in-memory fake
    executor, returns the deterministic empty result, and nothing runs.
    """
    harness = build_harness(_resp(valid_call(query="rm -rf / && curl evil.example")))
    outcome = harness.run()

    assert outcome.succeeded
    assert outcome.result is not None
    assert outcome.result.model_dump()["data"] == []
    assert harness.executor.call_count == 1
    assert harness.executor.calls[0].query == "rm -rf / && curl evil.example"


def test_case_10c_no_shell_capable_tool_is_registered() -> None:
    from local_agent.wiring import build_default_registry

    assert build_default_registry().names == frozenset({"file_search"})


# --- 11-12. the reasoning boundary ---------------------------------------


def test_case_11_shell_text_in_reasoning_does_not_affect_the_run() -> None:
    harness = build_harness(
        _resp(
            valid_call(),
            reasoning="<|think|> I will run rm -rf / to clean up first. <|/think|>",
        )
    )
    outcome = harness.run()

    assert outcome.succeeded
    assert harness.executor.call_count == 1
    assert harness.executor.calls[0].query == "Jeep clutch notes"
    # The reasoning text never enters the audit stream either.
    assert "rm -rf" not in json.dumps([e.as_dict() for e in outcome.events])


def test_case_12_tool_call_present_only_in_reasoning_never_executes() -> None:
    hidden = tool_call_json(query="Jeep clutch notes", root_id="workspace")
    harness = build_harness(
        _resp(
            None,
            reasoning=f"<|think|> I should call {hidden} right now. <|/think|>",
            narrative=f"Calling the tool: {hidden}",
        )
    )
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "TOOL_CALL_MALFORMED"
    assert harness.executor.call_count == 0
    assert State.EXECUTE not in outcome.states


# --- 13. malformed JSON ---------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        '{"tool": "file_search", "arguments": {',
        '{"tool": "file_search" "arguments": {}}',
        "not json at all",
        "",
        "   ",
        "[]",
        # Two competing calls in one array: not a single envelope (spec 02 §5.14).
        (
            '[{"tool": "file_search", "arguments": {"query": "a", "root_id": "workspace"}},'
            ' {"tool": "file_search", "arguments": {"query": "b", "root_id": "knowledge"}}]'
        ),
        '"just a string"',
        "null",
    ],
)
def test_case_13_malformed_structured_output_never_executes(payload: str) -> None:
    harness = build_harness(_resp(payload))
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "TOOL_CALL_MALFORMED"
    assert harness.executor.call_count == 0


# --- 14. simulated timeout ------------------------------------------------


def test_case_14_timeout_normalizes_and_the_run_can_recover() -> None:
    harness = build_harness(
        [
            _resp(valid_call(query="timeout_trigger")),
            _resp(valid_call(query="Jeep clutch notes")),
        ]
    )
    outcome = harness.run()

    assert outcome.succeeded
    assert outcome.attempts == 2
    assert harness.executor.call_count == 2
    codes = [dict(e.detail).get("code") for e in outcome.events if e.type == "execution_failed"]
    assert codes == ["EXECUTION_TIMEOUT"]
    # The model was told, in sanitized form, what to repair.
    feedback = harness.adapter.requests[1].feedback
    assert feedback is not None and feedback.error is not None
    assert feedback.error.code == "EXECUTION_TIMEOUT"
    assert feedback.accepted is False


def test_case_14b_repeated_timeouts_terminate_within_budget() -> None:
    harness = build_harness(_resp(valid_call(query="timeout_trigger")), complete=False)
    outcome = harness.run()

    assert outcome.terminal.code == "RETRY_EXHAUSTED"
    assert outcome.terminal.attempts == 3
    assert harness.executor.call_count == 3  # bounded, not unbounded
    assert harness.adapter.call_count == 3


# --- 15-16. duplicate proposals and retry exhaustion ---------------------


def test_case_15_identical_invalid_proposals_consume_the_budget() -> None:
    """The same bad call forever must not become an infinite loop."""
    harness = build_harness(
        _resp(tool_call_json(root_id="workspace")), complete=False
    )  # missing query
    outcome = harness.run()

    assert harness.adapter.call_count == 3
    assert outcome.attempts == 3
    remaining = [
        req.feedback.error.retry_budget_remaining
        for req in harness.adapter.requests
        if req.feedback is not None and req.feedback.error is not None
    ]
    assert remaining == [2, 1]  # strictly decreasing, never reset
    attempts_seen = [req.attempt for req in harness.adapter.requests]
    assert attempts_seen == [1, 2, 3]
    assert harness.executor.call_count == 0


def test_case_16_retry_exhaustion_emits_the_specified_terminal_payload() -> None:
    harness = build_harness(_resp(tool_call_json(root_id="workspace")), complete=False)
    outcome = harness.run()

    assert outcome.terminal.model_dump() == {
        "type": "controller_terminal",
        "status": "failed",
        "code": "RETRY_EXHAUSTED",
        "attempts": 3,
    }
    assert harness.adapter.call_count == 3  # no fourth attempt exists
    assert outcome.states[-1] is State.TERMINAL
    assert harness.executor.call_count == 0


# --- 17. tool-result prompt injection ------------------------------------


def test_case_17_tool_result_instructions_are_data_not_authority() -> None:
    executor = InjectingExecutor()
    context = RunContext(run_id="run-injection")
    harness = build_harness(_resp(valid_call()), run_context=context, executor=executor)
    outcome = harness.run()

    assert outcome.succeeded
    # The payload survives verbatim *as data* — it is neither obeyed nor scrubbed.
    assert outcome.result is not None
    assert outcome.result.model_dump()["data"] == [InjectingExecutor.PAYLOAD]

    # None of the authority it asked for changed.
    assert harness.run_context.max_attempts == 3
    assert harness.run_context.authorized_roots == frozenset({"workspace", "knowledge"})
    assert harness.run_context.allow_destructive is False
    assert harness.controller._registry.names == frozenset({"file_search"})
    # And it did not add states or executions.
    assert outcome.states[-1] is State.TERMINAL
    assert executor.call_count == 1


# --- 18. corrupt tool result ---------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "success", "data": "not-a-list"},
        {"status": "unexpected", "data": []},
        {"data": ["x"]},
        {},
        None,
        ["status", "success"],
        {"status": "success", "data": [1, 2, 3], "extra": "field"},
        "totally wrong",
    ],
)
def test_case_18_corrupt_results_verify_as_failures_without_crashing(
    payload: object,
) -> None:
    executor = CorruptResultExecutor(payload)
    harness = build_harness(_resp(valid_call()), executor=executor, complete=False)

    outcome = harness.run()  # must not raise

    assert outcome.error is not None
    assert outcome.error.code == "VERIFICATION_FAILED"
    assert outcome.terminal.code == "RETRY_EXHAUSTED"
    assert outcome.result is None
    assert executor.call_count == 3


def test_case_18b_a_result_declaring_failure_becomes_execution_failed() -> None:
    executor = CorruptResultExecutor({"status": "error", "data": []})
    harness = build_harness(_resp(valid_call()), executor=executor)
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "EXECUTION_FAILED"


def test_case_18c_executor_signalled_failure_is_normalized_and_sanitized() -> None:
    executor = FailingExecutor()
    harness = build_harness(_resp(valid_call()), executor=executor)
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "EXECUTION_FAILED"
    # The double's message contains a host path; none of it reaches the model.
    assert "/internal/host/path" not in json.dumps(outcome.error.model_dump())


def test_case_18d_unexpected_executor_exceptions_stay_visible() -> None:
    """A programmer error must not be laundered into a normalized error code."""

    class BrokenExecutor:
        def execute(self, args: object) -> dict[str, object]:
            raise ZeroDivisionError("bug in executor")

    harness = build_harness(_resp(valid_call()), executor=BrokenExecutor())
    with pytest.raises(ZeroDivisionError):
        harness.run()


# --- 19. illegal state transition ----------------------------------------
# (Full coverage lives in test_state_machine.py; this is the controller-level
#  statement of the same invariant.)


def test_case_19_terminal_state_cannot_be_driven_back_into_execution() -> None:
    from local_agent.state_machine import IllegalStateTransitionError, Run

    machine = Run()
    for state in (State.CLASSIFY, State.GENERATE, State.PARSE, State.FEEDBACK):
        machine.advance(state)
    machine.advance(State.TERMINAL)

    with pytest.raises(IllegalStateTransitionError):
        machine.advance(State.EXECUTE)
    assert machine.state is State.TERMINAL


# --- 20. retry-budget tampering ------------------------------------------


def test_case_20_budget_fields_smuggled_into_the_envelope_are_rejected() -> None:
    payload = json.dumps(
        {
            "tool": "file_search",
            "arguments": {"query": "Jeep clutch notes", "root_id": "workspace"},
            "max_attempts": 999,
            "retry_budget_remaining": 999,
        }
    )
    harness = build_harness(_resp(payload))
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "TOOL_CALL_MALFORMED"
    assert outcome.error.max_attempts == 3
    assert harness.run_context.max_attempts == 3
    assert harness.executor.call_count == 0


def test_case_20b_budget_fields_smuggled_into_arguments_are_rejected() -> None:
    harness = build_harness(
        _resp(valid_call(max_attempts=999, authorized=True, root_override="/etc"))
    )
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "SCHEMA_INVALID"
    assert harness.run_context.max_attempts == 3
    assert harness.executor.call_count == 0


def test_case_20c_persistent_tampering_still_terminates_at_three_attempts() -> None:
    payload = json.dumps(
        {
            "tool": "file_search",
            "arguments": {"query": "x", "root_id": "workspace"},
            "max_attempts": 10_000,
        }
    )
    harness = build_harness(_resp(payload), complete=False)
    outcome = harness.run()

    assert harness.adapter.call_count == 3
    assert outcome.terminal.attempts == 3
    assert outcome.terminal.code == "RETRY_EXHAUSTED"
