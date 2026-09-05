"""Mandatory architecture tests (task §"authority_tests").

Each test states one invariant from the authority model and demonstrates it
against the real controller. Where an invariant is structural — "the model
cannot modify schemas" — the test proves the structure, not a behaviour:
e.g. a frozen model raises on assignment, a registry exposes no mutator.
"""

from __future__ import annotations

import dataclasses
import json

import pytest
from conftest import InjectingExecutor, build_harness, tool_call_json, valid_call
from pydantic import ValidationError

from local_agent.contracts import ControllerError, FileSearchArgs, ModelResponse, ToolFeedback
from local_agent.policy import RunContext
from local_agent.state_machine import State
from local_agent.wiring import build_default_registry


def _resp(structured: str | None = None, **kw: str | None) -> ModelResponse:
    return ModelResponse(structured_output=structured, **kw)


# --- the LLM cannot execute tools directly --------------------------------


def test_llm_cannot_execute_tools_directly() -> None:
    """The model's entire surface is one text field; it holds no executor handle.

    `ModelResponse` carries no callable, no tool handle, no registry
    reference — only strings. There is therefore no representable model
    output that *is* an execution; every execution originates from
    `Controller._execute`, after five gates.
    """
    fields = ModelResponse.model_fields
    assert set(fields) == {"reasoning", "narrative", "structured_output"}
    for name, field in fields.items():
        assert field.annotation == str | None, name


def test_only_the_controller_calls_the_executor() -> None:
    """Grep-level proof: `.execute(` appears in exactly one production module."""
    import pathlib

    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "local_agent"
    callers = sorted(
        path.relative_to(src).as_posix()
        for path in src.rglob("*.py")
        if "executor.execute(" in path.read_text()
    )
    assert callers == ["controller.py"]


# --- the LLM cannot choose controller states ------------------------------


def test_llm_cannot_choose_controller_states() -> None:
    """No contract crossing the model boundary carries a state field."""
    from local_agent.contracts import ModelRequest, RawToolCall

    for model in (ModelResponse, RawToolCall):
        assert "state" not in model.model_fields
    # Even a candidate that names a state gets no purchase: the envelope
    # forbids unknown fields.
    harness = build_harness(
        _resp(json.dumps({"tool": "file_search", "arguments": {}, "state": "EXECUTE"}))
    )
    outcome = harness.run()
    assert outcome.error is not None
    assert outcome.error.code == "TOOL_CALL_MALFORMED"
    assert harness.executor.call_count == 0
    assert "state" not in ModelRequest.model_fields


# --- the LLM cannot increase retry limits ---------------------------------


def test_llm_cannot_increase_retry_limits() -> None:
    harness = build_harness(
        _resp(
            json.dumps(
                {
                    "tool": "file_search",
                    "arguments": {"query": "a", "root_id": "workspace", "max_attempts": 99},
                }
            )
        )
    )
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.max_attempts == 3
    assert harness.adapter.call_count == 3
    assert harness.run_context.max_attempts == 3


def test_the_retry_budget_lives_in_a_frozen_object() -> None:
    context = RunContext(run_id="run-frozen")
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.max_attempts = 999  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.authorized_roots = frozenset({"workspace", "knowledge", "root"})  # type: ignore[misc]


# --- the LLM cannot modify schemas ----------------------------------------


def test_llm_cannot_modify_schemas() -> None:
    """Argument instances are frozen and unknown fields are refused."""
    args = FileSearchArgs(query="notes", root_id="workspace")
    with pytest.raises(ValidationError):
        args.max_results = 5000  # type: ignore[misc]
    with pytest.raises(ValidationError):
        FileSearchArgs.model_validate({"query": "notes", "root_id": "workspace", "injected": "yes"})

    # The registry's schema binding is likewise immutable.
    spec = build_default_registry().get("file_search")
    assert spec is not None
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.args_schema = ModelResponse  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.name = "shell_exec"  # type: ignore[misc]


def test_llm_cannot_register_tools() -> None:
    """The registry exposes no mutation API at all — not even a private one."""
    registry = build_default_registry()
    mutators = [
        name
        for name in dir(registry)
        if not name.startswith("__")
        and any(word in name.lower() for word in ("register", "add", "set", "update", "remove"))
    ]
    assert mutators == []
    assert registry.names == frozenset({"file_search"})


# --- the LLM cannot authorize itself or bypass policy ---------------------


def test_llm_cannot_authorize_itself() -> None:
    context = RunContext(run_id="run-selfauth", authorized_roots=frozenset({"knowledge"}))
    payload = json.dumps(
        {
            "tool": "file_search",
            "arguments": {"query": "notes", "root_id": "workspace"},
        }
    )
    harness = build_harness(_resp(payload), run_context=context)
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "POLICY_DENIED"
    assert harness.executor.call_count == 0
    assert harness.run_context.authorized_roots == frozenset({"knowledge"})


def test_llm_cannot_bypass_policy_by_repeating_the_request() -> None:
    """A denial is not a retry prompt: the run ends on the first attempt."""
    context = RunContext(run_id="run-persist", max_results_ceiling=1)
    harness = build_harness(_resp(valid_call(max_results=50)), run_context=context)
    outcome = harness.run()

    assert outcome.terminal.code == "POLICY_DENIED"
    assert outcome.terminal.attempts == 1
    assert harness.adapter.call_count == 1
    assert harness.executor.call_count == 0


def test_policy_denial_does_not_disclose_the_gate_or_the_grants() -> None:
    """A denial must not become a bypass tutorial (spec §"feedback_security")."""
    context = RunContext(run_id="run-quiet", authorized_roots=frozenset({"knowledge"}))
    harness = build_harness(_resp(valid_call(root_id="workspace")), run_context=context)
    outcome = harness.run()

    assert outcome.error is not None
    serialized = json.dumps(outcome.error.model_dump()).lower()
    for leak in (
        "knowledge",
        "authorized_roots",
        "grant",
        "ceiling",
        "root_not_granted",
        "traceback",
        "runcontext",
        "/home/",
        "authorize",
    ):
        assert leak not in serialized, leak
    assert outcome.error.field_errors == []


# --- reasoning-only content cannot invoke tools ---------------------------


def test_reasoning_only_content_cannot_invoke_tools() -> None:
    hidden = tool_call_json(query="Jeep clutch notes", root_id="workspace")
    harness = build_harness(_resp(None, reasoning=hidden, narrative=hidden))
    outcome = harness.run()

    assert outcome.error is not None
    assert outcome.error.code == "TOOL_CALL_MALFORMED"
    assert harness.executor.call_count == 0


def test_the_parser_reads_only_the_approved_channel() -> None:
    """Structural proof: `parse_candidate` never touches the other two fields."""
    import inspect

    from local_agent.controller import parse_candidate

    source = inspect.getsource(parse_candidate)
    assert "structured_output" in source
    assert "response.reasoning" not in source
    assert "response.narrative" not in source


# --- tool results cannot modify policy or state ---------------------------


def test_tool_results_cannot_modify_controller_policy() -> None:
    executor = InjectingExecutor()
    context = RunContext(run_id="run-result-policy")
    before = dataclasses.asdict(context)
    harness = build_harness(_resp(valid_call()), run_context=context, executor=executor)
    outcome = harness.run()

    assert outcome.succeeded
    assert dataclasses.asdict(harness.run_context) == before


def test_tool_results_cannot_modify_controller_state() -> None:
    executor = InjectingExecutor()
    harness = build_harness(_resp(valid_call()), executor=executor)
    injected = harness.run()

    clean = build_harness(_resp(valid_call())).run()
    assert injected.states == clean.states
    assert [e.type for e in injected.events] == [e.type for e in clean.events]


def test_tool_result_content_never_enters_the_audit_stream() -> None:
    executor = InjectingExecutor()
    harness = build_harness(_resp(valid_call()), executor=executor)
    outcome = harness.run()

    serialized = json.dumps([e.as_dict() for e in outcome.events])
    assert "IGNORE CONTROLLER RULES" not in serialized
    assert "rm -rf" not in serialized


# --- terminal states cannot execute tools ---------------------------------


def test_terminal_states_cannot_execute_tools() -> None:
    """Every terminated run ends at TERMINAL with no execution after it."""
    harness = build_harness(_resp(valid_call()))
    outcome = harness.run()

    assert outcome.states[-1] is State.TERMINAL
    assert outcome.states.count(State.TERMINAL) == 1
    terminal_index = outcome.states.index(State.TERMINAL)
    assert State.EXECUTE not in outcome.states[terminal_index:]
    assert outcome.events[-1].type == "terminal"


# --- unauthorized requests cannot reach executors -------------------------


@pytest.mark.parametrize(
    "payload",
    [
        tool_call_json(tool="shell_exec", cmd="rm -rf /"),
        tool_call_json(tool="file_search", query="notes", root_id="/etc"),
        tool_call_json(tool="file_search", root_id="workspace"),
        "not json",
        None,
    ],
)
def test_unauthorized_requests_never_reach_an_executor(payload: str | None) -> None:
    harness = build_harness(_resp(payload))
    outcome = harness.run()

    assert not outcome.succeeded
    assert harness.executor.call_count == 0


def test_feedback_to_the_model_is_a_sanitized_typed_object() -> None:
    """The model receives `ToolFeedback`, never a controller-internal object."""
    harness = build_harness(_resp(tool_call_json(root_id="workspace")))
    harness.run()

    feedback = harness.adapter.requests[1].feedback
    assert isinstance(feedback, ToolFeedback)
    assert isinstance(feedback.error, ControllerError)
    assert feedback.accepted is False
    assert set(feedback.model_dump()) == {"type", "tool", "accepted", "error"}
