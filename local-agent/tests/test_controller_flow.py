"""Controller-level unit tests for the pieces the adversarial suite exercises
only indirectly: gate ordering, event emission, and budget arithmetic."""

from __future__ import annotations

import json

from conftest import build_harness, tool_call_json, valid_call

from local_agent.contracts import ModelResponse
from local_agent.policy import LEGAL_ROOT_IDS, Decision, RunContext, authorize, evaluate_policy
from local_agent.wiring import build_default_registry


def _resp(structured: str | None = None, **kw: str | None) -> ModelResponse:
    return ModelResponse(structured_output=structured, **kw)


# --- observability --------------------------------------------------------


def test_every_required_event_type_is_emitted_on_the_success_path() -> None:
    outcome = build_harness(_resp(valid_call())).run()
    types = {e.type for e in outcome.events}

    assert {
        "run_created",
        "state_entered",
        "model_output_received",
        "candidate_parsed",
        "execution_started",
        "execution_succeeded",
        "terminal",
    } <= types


def test_rejection_paths_emit_their_specific_events() -> None:
    cases = {
        "schema_rejected": _resp(tool_call_json(root_id="workspace")),
        "tool_not_found": _resp(tool_call_json(tool="nope")),
    }
    for expected, response in cases.items():
        outcome = build_harness(response).run()
        assert expected in {e.type for e in outcome.events}


def test_authorization_and_policy_rejections_are_separately_auditable() -> None:
    denied_auth = build_harness(
        _resp(valid_call(root_id="workspace")),
        run_context=RunContext(run_id="r", authorized_roots=frozenset({"knowledge"})),
    ).run()
    auth_events = [e for e in denied_auth.events if e.type == "authorization_rejected"]
    assert len(auth_events) == 1
    assert dict(auth_events[0].detail)["reason"] == "root_not_granted"

    denied_policy = build_harness(
        _resp(valid_call(max_results=20)),
        run_context=RunContext(run_id="r", max_results_ceiling=5),
    ).run()
    policy_events = [e for e in denied_policy.events if e.type == "policy_rejected"]
    assert len(policy_events) == 1
    assert dict(policy_events[0].detail)["reason"] == "max_results_above_policy_ceiling"


def test_retry_events_record_the_attempt_progression() -> None:
    outcome = build_harness(_resp(tool_call_json(root_id="workspace"))).run()
    retries = [dict(e.detail) for e in outcome.events if e.type == "retry"]
    assert retries == [
        {"attempt": 1, "next_attempt": 2},
        {"attempt": 2, "next_attempt": 3},
    ]


def test_audit_events_never_carry_model_or_argument_text() -> None:
    secret_query = "correlation-horse-battery-staple"
    outcome = build_harness(
        _resp(valid_call(query=secret_query), reasoning="secret reasoning text")
    ).run()

    serialized = json.dumps([e.as_dict() for e in outcome.events])
    assert secret_query not in serialized
    assert "secret reasoning text" not in serialized


# --- budget arithmetic ----------------------------------------------------


def test_retry_budget_remaining_counts_down_correctly() -> None:
    harness = build_harness(_resp(tool_call_json(root_id="workspace")))
    harness.run()

    errors = [
        req.feedback.error
        for req in harness.adapter.requests
        if req.feedback and req.feedback.error
    ]
    assert [(e.attempt, e.retry_budget_remaining, e.max_attempts) for e in errors] == [
        (1, 2, 3),
        (2, 1, 3),
    ]


def test_a_custom_budget_is_honoured_exactly() -> None:
    harness = build_harness(
        _resp(tool_call_json(root_id="workspace")),
        run_context=RunContext(run_id="r", max_attempts=5),
    )
    outcome = harness.run()

    assert harness.adapter.call_count == 5
    assert outcome.terminal.attempts == 5
    assert outcome.terminal.code == "RETRY_EXHAUSTED"


def test_a_single_attempt_budget_permits_no_retry() -> None:
    harness = build_harness(
        _resp(tool_call_json(root_id="workspace")),
        run_context=RunContext(run_id="r", max_attempts=1),
    )
    outcome = harness.run()

    assert harness.adapter.call_count == 1
    assert outcome.terminal.code == "RETRY_EXHAUSTED"


# --- gate units -----------------------------------------------------------


def test_authorize_and_policy_are_independent_functions() -> None:
    spec = build_default_registry().get("file_search")
    assert spec is not None
    from local_agent.contracts import FileSearchArgs

    args = FileSearchArgs(query="notes", root_id="workspace", max_results=10)

    granted = RunContext(run_id="r")
    assert authorize(spec, args, granted) == Decision(True, "ok")
    assert evaluate_policy(spec, args, granted) == Decision(True, "ok")

    # Authorization fails, policy would have passed.
    no_root = RunContext(run_id="r", authorized_roots=frozenset({"knowledge"}))
    assert authorize(spec, args, no_root).allowed is False
    assert evaluate_policy(spec, args, no_root).allowed is True

    # Authorization passes, policy fails.
    tight = RunContext(run_id="r", max_results_ceiling=1)
    assert authorize(spec, args, tight).allowed is True
    assert evaluate_policy(spec, args, tight).allowed is False


def test_ungranted_tools_are_denied_even_when_registered() -> None:
    spec = build_default_registry().get("file_search")
    assert spec is not None
    from local_agent.contracts import FileSearchArgs

    context = RunContext(run_id="r", authorized_tools=frozenset())
    decision = authorize(spec, FileSearchArgs(query="q", root_id="workspace"), context)
    assert decision == Decision(False, "tool_not_granted")


def test_run_context_rejects_roots_that_do_not_exist() -> None:
    import pytest

    with pytest.raises(ValueError, match="non-existent roots"):
        RunContext(run_id="r", authorized_roots=frozenset({"workspace", "root"}))

    with pytest.raises(ValueError, match="max_attempts"):
        RunContext(run_id="r", max_attempts=0)


def test_only_two_roots_exist_in_this_milestone() -> None:
    assert LEGAL_ROOT_IDS == frozenset({"workspace", "knowledge"})
