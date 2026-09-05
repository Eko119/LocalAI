"""Typed-contract unit tests: schemas, error protocol, and the fake executor."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from local_agent.contracts import (
    RETRYABLE_CODES,
    ControllerError,
    ControllerTerminal,
    FileSearchArgs,
    FileSearchResult,
    RawToolCall,
    ToolFeedback,
)
from local_agent.executors.file_search import FakeFileSearchExecutor

# --- FileSearchArgs -------------------------------------------------------


def test_defaults_match_the_contract() -> None:
    args = FileSearchArgs(query="notes", root_id="workspace")
    assert args.max_results == 10


@pytest.mark.parametrize("root_id", ["workspace", "knowledge"])
def test_both_legal_roots_are_accepted(root_id: str) -> None:
    args = FileSearchArgs.model_validate({"query": "notes", "root_id": root_id})
    assert args.root_id == root_id


@pytest.mark.parametrize(
    ("query", "max_results"),
    [("q", 1), ("q" * 500, 50), ("q" * 250, 25)],
)
def test_boundary_values_inside_the_range_are_accepted(query: str, max_results: int) -> None:
    args = FileSearchArgs(query=query, root_id="workspace", max_results=max_results)
    assert args.max_results == max_results


@pytest.mark.parametrize(
    "kwargs",
    [
        {"query": "", "root_id": "workspace"},
        {"query": "q" * 501, "root_id": "workspace"},
        {"query": "q", "root_id": "workspace", "max_results": 0},
        {"query": "q", "root_id": "workspace", "max_results": 51},
        {"query": "q", "root_id": "workspace", "max_results": -1},
        {"query": "q", "root_id": "root"},
        {"query": "q", "root_id": "/etc"},
        {"query": "q"},
        {"root_id": "workspace"},
        {"query": 42, "root_id": "workspace"},
        {"query": "q", "root_id": "workspace", "max_results": "ten"},
        {"query": "q", "root_id": "workspace", "unexpected": True},
    ],
)
def test_invalid_arguments_are_rejected(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        FileSearchArgs.model_validate(kwargs)


def test_arguments_are_immutable_once_validated() -> None:
    args = FileSearchArgs(query="notes", root_id="workspace")
    with pytest.raises(ValidationError):
        args.query = "something else"  # type: ignore[misc]


# --- error / feedback protocol -------------------------------------------


def test_controller_error_matches_the_specified_field_set() -> None:
    assert set(ControllerError.model_fields) == {
        "code",
        "retryable",
        "retry_budget_remaining",
        "message",
        "field_errors",
        "attempt",
        "max_attempts",
    }


def test_retry_eligibility_table_matches_the_specification() -> None:
    assert "SCHEMA_INVALID" in RETRYABLE_CODES
    assert "TOOL_CALL_MALFORMED" in RETRYABLE_CODES
    assert "EXECUTION_TIMEOUT" in RETRYABLE_CODES
    assert "VERIFICATION_FAILED" in RETRYABLE_CODES
    for non_retryable in ("POLICY_DENIED", "TOOL_NOT_FOUND", "RETRY_EXHAUSTED"):
        assert non_retryable not in RETRYABLE_CODES


def test_feedback_serializes_to_the_documented_shape() -> None:
    """Matches the worked example in spec 03 §6."""
    feedback = ToolFeedback(
        tool="file_search",
        accepted=False,
        error=ControllerError(
            code="SCHEMA_INVALID",
            retryable=True,
            retry_budget_remaining=2,
            message="Tool arguments failed schema validation.",
            field_errors=[{"field": "query", "reason": "must contain at least 1 character"}],
            attempt=1,
            max_attempts=3,
        ),
    )
    payload = feedback.model_dump()
    assert payload["type"] == "tool_feedback"
    assert payload["accepted"] is False
    assert payload["error"]["retry_budget_remaining"] == 2


def test_terminal_serializes_to_the_documented_shape() -> None:
    """Matches the worked example in spec 03 §7."""
    terminal = ControllerTerminal(status="failed", code="RETRY_EXHAUSTED", attempts=3)
    assert terminal.model_dump() == {
        "type": "controller_terminal",
        "status": "failed",
        "code": "RETRY_EXHAUSTED",
        "attempts": 3,
    }


def test_unknown_error_codes_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ControllerError(
            code="ACCESS_GRANTED",
            retryable=True,
            retry_budget_remaining=99,
            message="",
            attempt=1,
            max_attempts=3,
        )


def test_the_tool_call_envelope_forbids_extra_fields() -> None:
    assert RawToolCall(tool="file_search", arguments={}).arguments == {}
    with pytest.raises(ValidationError):
        RawToolCall(tool="file_search", arguments={}, max_attempts=99)  # type: ignore[call-arg]


# --- the fake executor ----------------------------------------------------


def test_fake_executor_fixtures_are_exactly_as_specified() -> None:
    executor = FakeFileSearchExecutor()
    hit = executor.execute(FileSearchArgs(query="Jeep clutch notes", root_id="workspace"))
    assert hit == {"status": "success", "data": ["clutch_replacement.md"]}

    miss = executor.execute(FileSearchArgs(query="anything else", root_id="knowledge"))
    assert miss == {"status": "success", "data": []}

    with pytest.raises(TimeoutError):
        executor.execute(FileSearchArgs(query="timeout_trigger", root_id="workspace"))


def test_fake_executor_is_deterministic_across_repetitions() -> None:
    executor = FakeFileSearchExecutor()
    args = FileSearchArgs(query="Jeep clutch notes", root_id="workspace")
    results = [executor.execute(args) for _ in range(100)]
    assert all(r == results[0] for r in results)
    assert executor.call_count == 100


def test_fake_executor_ignores_root_and_max_results_deterministically() -> None:
    """The fixture is keyed on query alone; other legal inputs do not perturb it."""
    executor = FakeFileSearchExecutor()
    a = executor.execute(
        FileSearchArgs(query="Jeep clutch notes", root_id="workspace", max_results=1)
    )
    b = executor.execute(
        FileSearchArgs(query="Jeep clutch notes", root_id="knowledge", max_results=50)
    )
    assert a == b


def test_executor_results_satisfy_the_declared_result_schema() -> None:
    executor = FakeFileSearchExecutor()
    raw = executor.execute(FileSearchArgs(query="Jeep clutch notes", root_id="workspace"))
    assert FileSearchResult.model_validate(raw).data == ["clutch_replacement.md"]
