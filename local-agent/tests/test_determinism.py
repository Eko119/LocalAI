"""Deterministic replay (task §"deterministic_replay", spec 09 §"Determinism test").

The same fake-model event sequence is executed 200 times per scenario. What
must be byte-identical across every repetition:

* the state transition sequence
* authorization and policy decisions
* tool execution decisions (which, how many, with what arguments)
* retry counts
* the terminal outcome
* the full structured audit trace

The scenarios deliberately span all four terminal shapes — success, a
schema-retry loop ending in RETRY_EXHAUSTED, an immediate non-retryable
denial, and a mid-run timeout recovery — so determinism is proven on the
retry and rejection paths, not just the happy one.
"""

from __future__ import annotations

import json

import pytest
from conftest import build_harness, tool_call_json, valid_call

from local_agent.contracts import ModelResponse
from local_agent.policy import RunContext

REPETITIONS = 200


def _resp(structured: str | None = None, **kw: str | None) -> ModelResponse:
    return ModelResponse(structured_output=structured, **kw)


def _scenarios() -> dict[str, tuple[list[ModelResponse], RunContext]]:
    return {
        "success": ([_resp(valid_call())], RunContext(run_id="replay")),
        "schema_retry_exhaustion": (
            [_resp(tool_call_json(root_id="workspace"))],
            RunContext(run_id="replay"),
        ),
        "non_retryable_denial": (
            [_resp(valid_call(root_id="workspace"))],
            RunContext(run_id="replay", authorized_roots=frozenset({"knowledge"})),
        ),
        "timeout_then_recovery": (
            [
                _resp(valid_call(query="timeout_trigger")),
                _resp(valid_call(query="Jeep clutch notes")),
            ],
            RunContext(run_id="replay"),
        ),
        "reasoning_only_then_valid": (
            [
                _resp(None, reasoning=tool_call_json(query="x", root_id="workspace")),
                _resp(valid_call()),
            ],
            RunContext(run_id="replay"),
        ),
    }


def _fingerprint(scenario: str) -> str:
    """One run reduced to a comparable string covering every deterministic axis."""
    responses, context = _scenarios()[scenario]
    harness = build_harness(responses, run_context=context)
    outcome = harness.run()

    return json.dumps(
        {
            "states": [s.value for s in outcome.states],
            "events": [e.as_dict() for e in outcome.events],
            "terminal": outcome.terminal.model_dump(),
            "attempts": outcome.attempts,
            "error": outcome.error.model_dump() if outcome.error else None,
            "result": outcome.result.model_dump() if outcome.result else None,
            "model_calls": harness.adapter.call_count,
            "executor_calls": harness.executor.call_count,
            "executed_arguments": [a.model_dump() for a in harness.executor.calls],
            # Sanitized feedback the controller chose to send back each round.
            "feedback": [
                req.feedback.model_dump() if req.feedback else None
                for req in harness.adapter.requests
            ],
        },
        sort_keys=True,
    )


@pytest.mark.parametrize("scenario", sorted(_scenarios()))
def test_replay_is_identical_across_repetitions(scenario: str) -> None:
    baseline = _fingerprint(scenario)
    fingerprints = {_fingerprint(scenario) for _ in range(REPETITIONS)}

    assert fingerprints == {baseline}, f"{scenario} diverged across {REPETITIONS} runs"


def test_scenarios_actually_differ_from_one_another() -> None:
    """Guard against a fingerprint so lossy that everything looks identical."""
    fingerprints = {name: _fingerprint(name) for name in _scenarios()}
    assert len(set(fingerprints.values())) == len(fingerprints)


def test_audit_events_contain_no_wall_clock_or_random_fields() -> None:
    """Determinism depends on events carrying no ambient nondeterminism."""
    outcome = build_harness(_resp(valid_call())).run()

    forbidden = {
        "timestamp",
        "time",
        "ts",
        "now",
        "clock",
        "uuid",
        "guid",
        "nonce",
        "random",
        "duration",
        "elapsed",
        "pid",
        "hostname",
    }
    for event in outcome.events:
        keys = {key.lower() for key in set(event.as_dict()) | set(dict(event.detail))}
        assert not keys & forbidden, event
        assert not any(key.endswith("_at") for key in keys), event


def test_sequence_numbers_are_monotonic_from_zero() -> None:
    outcome = build_harness(_resp(valid_call())).run()
    assert [e.seq for e in outcome.events] == list(range(len(outcome.events)))
