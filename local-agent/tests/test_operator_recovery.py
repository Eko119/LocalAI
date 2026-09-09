"""Operator-controlled recovery, end to end, against the real controller.

Where `test_operator.py` asks what an operator can *say*, this file asks what
happens when the controller acts on it: which crash windows leave which state,
whether a resume really re-enters the ordinary execution path, whether an abort
stays an abort, and whether anything about the control plane leaks into the
model's view of the world.

Every crash is a `SimulatedCrash` raised at a chosen structural boundary. There
are no sleeps and no timing anywhere in this file — a timing-dependent crash
test would be both slow and non-deterministic, and `test_determinism.py` exists
to forbid exactly that.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    COMPLETION_RESPONSE,
    RECOVERY_MESSAGES,
    VALID_PROPOSAL,
    CrashingJournal,
    CrashingReadJournal,
    MutatingJournal,
    SimulatedCrash,
    build_recovery_harness,
    crash_mid_execution,
    unsafe_registry,
)

from local_agent.contracts import ModelResponse
from local_agent.controller import Controller, RecoveryRefused
from local_agent.executors.file_search import FakeFileSearchExecutor
from local_agent.model_adapter import ScriptedModelAdapter
from local_agent.operator import OperatorDecision, OperatorDecisionRejected
from local_agent.persistence.journal import JournalLockError, RunJournal
from local_agent.policy import RunContext
from local_agent.recovery import plan_recovery, replay
from local_agent.registry import ToolRegistry
from local_agent.wiring import build_default_registry


def _harness(
    tmp_path: Path, *, repeatable: bool = True, run_id: str = "run-crashed", **kwargs: Any
) -> Any:
    crashed = crash_mid_execution(tmp_path, run_id=run_id, repeatable=repeatable)
    return build_recovery_harness(crashed, repeatable=repeatable, **kwargs)


def _records(path: Path) -> list[tuple[int, Any]]:
    with RunJournal(path) as journal:
        return journal.records()


def _types(path: Path) -> tuple[str, ...]:
    return tuple(record.type for _, record in _records(path))


# ===========================================================================
# Task 9: the safe resume path
# ===========================================================================


def test_a_resume_re_executes_the_original_tool_with_the_original_arguments(
    tmp_path: Path,
) -> None:
    """The operator approves; the controller runs *its own* recorded operation."""
    harness = _harness(tmp_path)
    plan = harness.plan()
    outcome = harness.recover(harness.decide("resume", "verified_safe_to_repeat"))

    assert outcome.executed is True
    assert outcome.action == "resume"
    assert harness.executor.call_count == 1
    executed = harness.executor.calls[0]
    assert executed.model_dump(mode="json") == plan.arguments
    assert outcome.execution_id == plan.execution_id


def test_a_resume_walks_the_ordinary_gates_in_the_ordinary_order(tmp_path: Path) -> None:
    """No recovery-specific execution path exists, so the state trace is the usual one."""
    harness = _harness(tmp_path)
    outcome = harness.recover(harness.decide("resume", "verified_safe_to_repeat"))

    assert outcome.run is not None
    assert [state.value for state in outcome.run.states] == [
        "RECEIVE",
        "CLASSIFY",
        "GENERATE",
        "PARSE",
        "VALIDATE",
        "AUTHORIZE",
        "POLICY_CHECK",
        "EXECUTE",
        "VERIFY",
        "RESPOND",
        "TERMINAL",
    ]


def test_a_resume_preserves_the_execution_identity_rather_than_minting_a_new_one(
    tmp_path: Path,
) -> None:
    """One authorization, one identity, one completion — not two of anything."""
    harness = _harness(tmp_path)
    plan = harness.plan()
    harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    harness.journal.close()

    records = _records(harness.journal.path)
    authorizations = [r for _, r in records if r.type == "execution_authorized"]
    completions = [r for _, r in records if r.type == "execution_completed"]

    assert len(authorizations) == 1
    assert len(completions) == 1
    assert authorizations[0].execution_id == plan.execution_id
    assert completions[0].execution_id == plan.execution_id


def test_a_resume_produces_the_ordinary_verified_result(tmp_path: Path) -> None:
    harness = _harness(tmp_path)
    outcome = harness.recover(harness.decide("resume", "verified_safe_to_repeat"))

    assert outcome.run is not None
    assert outcome.run.succeeded is True
    assert outcome.run.result is not None
    assert outcome.run.result.model_dump(mode="json") == {
        "status": "success",
        "data": ["clutch_replacement.md"],
    }


def test_recovery_without_a_journal_is_refused(tmp_path: Path) -> None:
    """Recovery is about durable evidence; without any there is nothing to do."""
    controller = Controller(
        build_default_registry(FakeFileSearchExecutor()),
        ScriptedModelAdapter((ModelResponse(structured_output=VALID_PROPOSAL),)),
    )
    decision = OperatorDecision(
        run_id="run-x", plan_id="a" * 32, action="abort", decision_sequence=1, reason_code="stop"
    )
    with pytest.raises(RecoveryRefused) as caught:
        asyncio.run(controller.recover(RunContext(run_id="run-x"), decision))
    assert caught.value.reason == "recovery_requires_a_journal"


# ===========================================================================
# Task 8: immediate revalidation, after the decision is durable
# ===========================================================================


def test_a_registry_swapped_after_approval_is_caught_before_the_executor(
    tmp_path: Path,
) -> None:
    """Mid-flight mutation: the tool disappears once the decision is recorded.

    This is the case the binding check alone cannot catch, because the decision
    was valid when it was made. Revalidation runs after persistence and before
    any executor, so the swap is caught with nothing executed.
    """
    crashed = crash_mid_execution(tmp_path)
    spy = FakeFileSearchExecutor()
    holder: dict[str, Any] = {}

    def empty_the_registry() -> None:
        holder["controller"]._registry = ToolRegistry(())

    journal = MutatingJournal(crashed.path, after="operator_decision", mutate=empty_the_registry)
    harness = build_recovery_harness(crashed, journal=journal)
    harness.controller._registry = build_default_registry(spy)
    harness.registry = harness.controller._registry
    holder["controller"] = harness.controller

    with pytest.raises(Exception) as caught:
        harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    assert journal.fired is True
    assert spy.call_count == 0
    assert "journal_tool_not_in_registry" in str(caught.value)


def test_grants_narrowed_after_approval_are_caught_before_the_executor(
    tmp_path: Path,
) -> None:
    """The gates are re-run at recovery time, not read from the record."""
    crashed = crash_mid_execution(tmp_path)
    harness = build_recovery_harness(
        crashed, run_context=RunContext(run_id=crashed.run_id, authorized_tools=frozenset())
    )
    plan = harness.plan()

    assert "resume" not in plan.available_actions
    decision = OperatorDecision(
        run_id=plan.run_id,
        plan_id=plan.plan_id,
        action="resume",
        decision_sequence=plan.next_decision_sequence,
        reason_code="try_anyway",
        expected_execution_id=plan.execution_id,
    )
    with pytest.raises(OperatorDecisionRejected):
        harness.recover(decision)
    assert harness.executor.call_count == 0


def test_a_budget_change_after_approval_stops_recovery(tmp_path: Path) -> None:
    """`RunContext` is authority; a journal written under a different one is refused."""
    crashed = crash_mid_execution(tmp_path)
    harness = build_recovery_harness(
        crashed, run_context=RunContext(run_id=crashed.run_id, max_attempts=9)
    )
    with pytest.raises(Exception) as caught:
        harness.plan()
    assert "journal_budget_mismatch" in str(caught.value)
    assert harness.executor.call_count == 0


def test_a_side_effect_flag_change_after_the_crash_stops_recovery(tmp_path: Path) -> None:
    """The live ToolSpec decides repeatability; the record must agree with it."""
    crashed = crash_mid_execution(tmp_path, repeatable=True)
    spy = FakeFileSearchExecutor()
    harness = build_recovery_harness(crashed, registry=unsafe_registry(spy))

    with pytest.raises(Exception) as caught:
        harness.plan()
    assert "journal_side_effect_flag_mismatch" in str(caught.value)
    assert spy.call_count == 0


# ===========================================================================
# Task 18: crash windows around operator-controlled recovery
#
# Several of these land on the same structural boundary, because the journal
# has no durable record between them. They are kept as separate named tests
# with different assertions rather than collapsed, since each names a distinct
# question an operator would ask — but the report says plainly which coincide.
# ===========================================================================


def test_window_1_crash_during_plan_generation_records_nothing(tmp_path: Path) -> None:
    crashed = crash_mid_execution(tmp_path)
    before = _types(crashed.path)
    journal = CrashingReadJournal(crashed.path, crash_on_read=1)
    harness = build_recovery_harness(crashed, journal=journal)

    journal.arm()
    with pytest.raises(SimulatedCrash):
        harness.recover(
            OperatorDecision(
                run_id=crashed.run_id,
                plan_id="a" * 32,
                action="abort",
                decision_sequence=1,
                reason_code="never_landed",
            )
        )
    journal.close()

    assert _types(crashed.path) == before
    assert harness.executor.call_count == 0


def test_window_2_crash_before_the_decision_is_persisted_leaves_the_run_recoverable(
    tmp_path: Path,
) -> None:
    crashed = crash_mid_execution(tmp_path)
    journal = CrashingJournal(crashed.path, crash_before="operator_decision")
    harness = build_recovery_harness(crashed, journal=journal)

    with pytest.raises(SimulatedCrash):
        harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    journal.close()

    assert "operator_decision" not in _types(crashed.path)
    assert harness.executor.call_count == 0
    # The run is exactly where it was: still awaiting a decision.
    fresh = build_recovery_harness(crashed)
    assert fresh.plan().disposition == "execution_pending_repeatable"
    assert fresh.plan().next_decision_sequence == 1


def test_window_3_crash_after_the_approval_is_persisted_requires_a_new_decision(
    tmp_path: Path,
) -> None:
    """The approval survived, and is worth nothing on its own.

    This is the window that would be dangerous if a recorded approval were
    treated as standing permission. It is not: recording it changed the plan's
    identity, so the run needs a fresh plan and a fresh decision.
    """
    crashed = crash_mid_execution(tmp_path)
    journal = CrashingJournal(crashed.path, crash_after="operator_decision")
    harness = build_recovery_harness(crashed, journal=journal)
    approval = harness.decide("resume", "verified_safe_to_repeat")

    with pytest.raises(SimulatedCrash):
        harness.recover(approval)
    journal.close()

    assert "operator_decision" in _types(crashed.path)
    assert harness.executor.call_count == 0

    fresh = build_recovery_harness(crashed)
    plan = fresh.plan()
    assert plan.decisions_recorded == 1
    assert plan.next_decision_sequence == 2
    with pytest.raises(OperatorDecisionRejected) as caught:
        fresh.recover(approval)
    assert caught.value.reason == "decision_plan_id_mismatch"
    assert fresh.executor.call_count == 0


def test_window_4_crash_before_revalidation_executes_nothing(tmp_path: Path) -> None:
    """Dying on the second journal read, between persistence and revalidation."""
    crashed = crash_mid_execution(tmp_path)
    journal = CrashingReadJournal(crashed.path, crash_on_read=2)
    harness = build_recovery_harness(crashed, journal=journal)
    decision = harness.decide("resume", "verified_safe_to_repeat")

    # Armed only now: read 1 is the controller deriving the plan, read 2 is
    # the re-derivation inside immediate revalidation.
    journal.arm()
    with pytest.raises(SimulatedCrash):
        harness.recover(decision)
    journal.close()

    assert journal.reads == 2
    assert "operator_decision" in _types(crashed.path)
    assert "execution_completed" not in _types(crashed.path)
    assert harness.executor.call_count == 0


def test_window_5_crash_after_revalidation_but_before_the_physical_call(
    tmp_path: Path,
) -> None:
    """The executor was reached and produced no effect.

    Structurally the same point as window 6 — there is no durable record
    between "revalidated" and "invoked" — so the two are distinguished by what
    they assert rather than by where they crash.
    """
    from conftest import CrashBeforeExecuteExecutor

    crashed = crash_mid_execution(tmp_path)
    inner = FakeFileSearchExecutor()
    dying = CrashBeforeExecuteExecutor(inner)
    harness = build_recovery_harness(crashed, registry=build_default_registry(dying))

    with pytest.raises(SimulatedCrash):
        harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    harness.journal.close()

    assert dying.call_count == 1  # the executor was reached
    assert inner.call_count == 0  # and nothing physical happened
    assert "execution_completed" not in _types(crashed.path)


def test_window_6_the_ambiguity_window_reopens_unchanged(tmp_path: Path) -> None:
    """Same crash point as window 5, asked as a recovery question."""
    from conftest import CrashBeforeExecuteExecutor

    crashed = crash_mid_execution(tmp_path)
    dying = CrashBeforeExecuteExecutor(FakeFileSearchExecutor())
    harness = build_recovery_harness(crashed, registry=build_default_registry(dying))
    with pytest.raises(SimulatedCrash):
        harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    harness.journal.close()

    fresh = build_recovery_harness(crashed)
    plan = fresh.plan()
    assert plan.disposition == "execution_pending_repeatable"
    assert "resume" in plan.available_actions
    assert plan.next_decision_sequence == 2  # a *new* decision is required


def test_window_7_crash_during_the_resumed_execution_stays_ambiguous(tmp_path: Path) -> None:
    """A resume can crash exactly as the original run did, and says so."""
    from conftest import CrashingExecutor

    crashed = crash_mid_execution(tmp_path)
    inner = FakeFileSearchExecutor()
    dying = CrashingExecutor(inner)
    harness = build_recovery_harness(crashed, registry=build_default_registry(dying))

    with pytest.raises(SimulatedCrash):
        harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    harness.journal.close()

    assert inner.call_count == 1  # the physical call happened this time
    assert "execution_completed" not in _types(crashed.path)
    fresh = build_recovery_harness(crashed)
    assert fresh.plan().disposition == "execution_pending_repeatable"


def test_window_8_crash_before_the_completion_is_persisted(tmp_path: Path) -> None:
    crashed = crash_mid_execution(tmp_path)
    journal = CrashingJournal(crashed.path, crash_before="execution_completed")
    spy = FakeFileSearchExecutor()
    harness = build_recovery_harness(crashed, journal=journal, registry=build_default_registry(spy))

    with pytest.raises(SimulatedCrash):
        harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    journal.close()

    assert spy.call_count == 1  # it ran
    assert "execution_completed" not in _types(crashed.path)  # nobody knows
    assert build_recovery_harness(crashed).plan().disposition == "execution_pending_repeatable"


def test_window_9_crash_after_the_completion_is_persisted_closes_the_window(
    tmp_path: Path,
) -> None:
    crashed = crash_mid_execution(tmp_path)
    journal = CrashingJournal(crashed.path, crash_after="execution_completed")
    spy = FakeFileSearchExecutor()
    harness = build_recovery_harness(crashed, journal=journal, registry=build_default_registry(spy))

    with pytest.raises(SimulatedCrash):
        harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    journal.close()

    fresh = build_recovery_harness(crashed)
    plan = fresh.plan()
    assert plan.disposition == "execution_completed"
    assert "resume" not in plan.available_actions  # the result is gone; do not repeat it
    assert plan.execution_status == "succeeded"


def test_window_10_crash_after_verification_leaves_a_completed_execution(
    tmp_path: Path,
) -> None:
    """Verification happened in-process and left no durable trace of its own.

    Same injection point as window 11: the next durable write after VERIFY is
    the terminal record, so "after verification" and "before terminal" are one
    boundary. What distinguishes them is the question — this one asks whether
    the execution is known to have finished.
    """
    crashed = crash_mid_execution(tmp_path)
    journal = CrashingJournal(crashed.path, crash_before="run_terminal")
    spy = FakeFileSearchExecutor()
    harness = build_recovery_harness(crashed, journal=journal, registry=build_default_registry(spy))

    with pytest.raises(SimulatedCrash):
        harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    journal.close()

    assert spy.call_count == 1
    assert "execution_completed" in _types(crashed.path)
    assert build_recovery_harness(crashed).plan().execution_status == "succeeded"


def test_window_11_crash_before_the_terminal_leaves_the_run_open(tmp_path: Path) -> None:
    crashed = crash_mid_execution(tmp_path)
    journal = CrashingJournal(crashed.path, crash_before="run_terminal")
    harness = build_recovery_harness(crashed, journal=journal)

    with pytest.raises(SimulatedCrash):
        harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    journal.close()

    assert "run_terminal" not in _types(crashed.path)
    plan = build_recovery_harness(crashed).plan()
    assert plan.is_terminal is False
    # Nothing further may execute: the physical call already completed.
    assert "resume" not in plan.available_actions
    assert plan.available_actions == ("abort", "terminalize", "acknowledge", "reject_recovery")


def test_window_12_crash_after_the_terminal_leaves_the_run_final(tmp_path: Path) -> None:
    crashed = crash_mid_execution(tmp_path)
    journal = CrashingJournal(crashed.path, crash_after="run_terminal")
    harness = build_recovery_harness(crashed, journal=journal)

    with pytest.raises(SimulatedCrash):
        harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    journal.close()

    plan = build_recovery_harness(crashed).plan()
    assert plan.is_terminal is True
    assert plan.terminal_status == "succeeded"
    assert plan.available_actions == ()


@pytest.mark.parametrize("moment", ["before", "after"])
def test_window_13_crash_around_the_abort_decision(tmp_path: Path, moment: str) -> None:
    """An abort that did not land is not an abort; one that landed is durable."""
    crashed = crash_mid_execution(tmp_path)
    kwargs = {f"crash_{moment}": "operator_decision"}
    journal = CrashingJournal(crashed.path, **kwargs)
    harness = build_recovery_harness(crashed, journal=journal)

    with pytest.raises(SimulatedCrash):
        harness.recover(harness.decide("abort", "operator_stop"))
    journal.close()

    types = _types(crashed.path)
    assert "run_terminal" not in types  # the terminal never got written either way
    assert ("operator_decision" in types) is (moment == "after")

    plan = build_recovery_harness(crashed).plan()
    assert plan.is_terminal is False
    assert plan.decisions_recorded == (1 if moment == "after" else 0)
    assert harness.executor.call_count == 0


# ===========================================================================
# Tasks 12, 13, 21, 24: abort semantics
# ===========================================================================


def test_an_abort_calls_no_executor_no_model_and_fabricates_nothing(tmp_path: Path) -> None:
    """The explicit abort test (task 21), stated as its three counters."""
    harness = _harness(tmp_path, repeatable=False)
    outcome = harness.recover(harness.decide("abort", "side_effect_cannot_be_confirmed"))

    assert outcome.terminal is True
    assert outcome.terminal_status == "aborted"
    assert outcome.executed is False
    assert outcome.run is None  # no RunOutcome means no synthesised tool result
    assert harness.executor.call_count == 0
    assert harness.adapter.call_count == 0


def test_an_abort_is_not_recorded_as_a_tool_failure(tmp_path: Path) -> None:
    """No synthetic ToolExecutionError, no synthetic completion, no fake result."""
    harness = _harness(tmp_path, repeatable=False)
    harness.recover(harness.decide("abort", "side_effect_cannot_be_confirmed"))
    harness.journal.close()

    records = _records(harness.journal.path)
    assert not [r for _, r in records if r.type == "execution_completed"]
    terminal = [r for _, r in records if r.type == "run_terminal"]
    assert len(terminal) == 1
    assert terminal[0].status == "aborted"
    assert terminal[0].code == "OPERATOR_ABORT"


def test_an_abort_preserves_execution_ambiguity(tmp_path: Path) -> None:
    """Task 13: abort means "no further execution", never "it did not happen".

    The three facts stay separately visible on disk — an authorization with no
    completion, an operator decision, and an aborted terminal — so nobody
    reading this journal later can mistake an unknown outcome for a
    non-execution.
    """
    harness = _harness(tmp_path, repeatable=False)
    before = harness.plan()
    assert before.disposition == "execution_unknown"

    harness.recover(harness.decide("abort", "side_effect_cannot_be_confirmed"))
    harness.journal.close()

    types = _types(harness.journal.path)
    assert "execution_authorized" in types
    assert "execution_completed" not in types  # the ambiguity is still recorded
    assert "operator_decision" in types
    assert "run_terminal" in types

    trace = replay(_records(harness.journal.path), harness.registry, harness.run_context)
    assert trace.terminal_status == "aborted"
    assert trace.operator_actions == ("abort",)
    assert trace.executions_completed == 0


def test_after_an_abort_nothing_can_execute_retry_or_be_approved(tmp_path: Path) -> None:
    """Task 24, as one assertion per prohibited outcome."""
    harness = _harness(tmp_path, repeatable=False)
    harness.recover(harness.decide("abort", "side_effect_cannot_be_confirmed"))
    plan = harness.plan()

    assert plan.is_terminal is True
    assert plan.available_actions == ()
    for action in ("resume", "abort", "acknowledge"):
        decision = OperatorDecision(
            run_id=plan.run_id,
            plan_id=plan.plan_id,
            action=action,
            decision_sequence=plan.next_decision_sequence,
            reason_code="after_abort",
            expected_execution_id=plan.execution_id,
        )
        with pytest.raises(OperatorDecisionRejected):
            harness.recover(decision)

    assert harness.executor.call_count == 0
    assert harness.adapter.call_count == 0


def test_terminalize_records_a_failure_rather_than_an_abort(tmp_path: Path) -> None:
    """Two terminal actions, two recorded intents — the audit keeps them apart."""
    harness = _harness(tmp_path, repeatable=False)
    outcome = harness.recover(harness.decide("terminalize", "unrecoverable_state"))
    harness.journal.close()

    assert outcome.terminal_status == "failed"
    terminal = [r for _, r in _records(harness.journal.path) if r.type == "run_terminal"]
    assert terminal[0].code == "OPERATOR_TERMINALIZED"


@pytest.mark.parametrize("action", ["acknowledge", "reject_recovery"])
def test_a_passive_decision_changes_nothing_but_the_plan(tmp_path: Path, action: str) -> None:
    harness = _harness(tmp_path)
    outcome = harness.recover(harness.decide(action, "not_yet"))

    assert outcome.terminal is False
    assert outcome.executed is False
    assert harness.executor.call_count == 0
    assert harness.adapter.call_count == 0
    plan = harness.plan()
    assert plan.disposition == "execution_pending_repeatable"
    assert plan.decisions_recorded == 1


# ===========================================================================
# Task 17: concurrency
# ===========================================================================


def test_two_live_journal_holders_cannot_both_recover(tmp_path: Path) -> None:
    """The existing advisory lock is the mechanism; no new locking was invented."""
    crashed = crash_mid_execution(tmp_path)
    with RunJournal(crashed.path), pytest.raises(JournalLockError):
        RunJournal(crashed.path)


def test_two_sequential_resume_attempts_execute_at_most_once(tmp_path: Path) -> None:
    """Two controllers, one journal, one approval: the second is refused.

    Not "exactly once" — the guarantee is that a single approval authorizes a
    single attempt. The first attempt's decision changes the plan, so the
    second controller's identical decision no longer names a plan that exists.
    """
    crashed = crash_mid_execution(tmp_path)
    journal = RunJournal(crashed.path)
    first = build_recovery_harness(crashed, journal=journal)
    second = build_recovery_harness(crashed, journal=journal)
    approval = first.decide("resume", "verified_safe_to_repeat")

    first.recover(approval)
    with pytest.raises(OperatorDecisionRejected):
        second.recover(approval)
    journal.close()

    assert first.executor.call_count == 1
    assert second.executor.call_count == 0
    completions = [r for _, r in _records(crashed.path) if r.type == "execution_completed"]
    assert len(completions) == 1


# ===========================================================================
# Tasks 11, 20, 22: recovery transparency and model-context security
# ===========================================================================


def test_recovery_makes_no_model_call_at_any_point(tmp_path: Path) -> None:
    """Task 10, measured rather than asserted structurally."""
    harness = _harness(tmp_path)
    harness.inspect()
    harness.plan()
    harness.recover(harness.decide("resume", "verified_safe_to_repeat"))

    assert harness.adapter.call_count == 0


def test_a_successful_resume_exposes_no_recovery_metadata_to_the_model(
    tmp_path: Path,
) -> None:
    """Task 22, with sentinels for every control-plane value.

    A successful resume terminates the run without another generation, so the
    strongest available statement is that the model was asked nothing at all
    and that no recovery value appears anywhere it could have been asked.
    """
    harness = _harness(tmp_path)
    plan = harness.plan()
    sentinel_reason = "sentinel_operator_reason_zx91"
    outcome = harness.recover(harness.decide("resume", sentinel_reason))

    assert outcome.run is not None
    assert harness.adapter.call_count == 0
    seen = json.dumps([request.model_dump(mode="json") for request in harness.adapter.requests])
    for sentinel in (
        plan.plan_id,
        plan.execution_id,
        sentinel_reason,
        plan.reason_code,
        "operator",
        "recovery",
        "journal",
    ):
        assert sentinel is not None
        assert sentinel not in seen


def test_a_resumed_run_that_continues_sends_the_model_nothing_about_recovery(
    tmp_path: Path,
) -> None:
    """The continuation case: a resumed execution fails, so a new generation runs.

    This is where a leak would actually show up, because the model *is* asked
    again. What it receives is the ordinary sanitized `ToolFeedback` — an error
    code and a message — and nothing about the plan, the decision, the
    execution identity, or the journal.
    """
    from conftest import FailingExecutor

    crashed = crash_mid_execution(tmp_path)
    failing = FailingExecutor()
    harness = build_recovery_harness(crashed, registry=build_default_registry(failing))
    plan = harness.plan()
    sentinel_reason = "sentinel_operator_reason_qq42"

    outcome = harness.recover(harness.decide("resume", sentinel_reason))

    # The resumed execution failed, the budget allowed another attempt, and the
    # controller went back to the model — the ordinary continuation.
    assert harness.adapter.call_count >= 1
    assert outcome.run is not None
    seen = json.dumps([request.model_dump(mode="json") for request in harness.adapter.requests])
    for sentinel in (plan.plan_id, plan.execution_id, sentinel_reason, "operator", "recovery"):
        assert sentinel is not None
        assert sentinel not in seen
    # And what the model *did* receive is the ordinary feedback contract.
    feedback = harness.adapter.requests[0].feedback
    assert feedback is not None
    assert feedback.error is not None
    assert feedback.error.code == "EXECUTION_FAILED"


def test_operator_reason_codes_never_reach_the_model(tmp_path: Path) -> None:
    """Belt and braces: a recorded reason is journal-only, on every path."""
    from conftest import FailingExecutor

    crashed = crash_mid_execution(tmp_path)
    harness = build_recovery_harness(crashed, registry=build_default_registry(FailingExecutor()))
    harness.recover(harness.decide("resume", "sentinel_reason_never_shown"))
    harness.journal.close()

    seen = json.dumps([request.model_dump(mode="json") for request in harness.adapter.requests])
    assert "sentinel_reason_never_shown" not in seen
    # It *is* in the journal, which is where an audit expects to find it.
    assert "sentinel_reason_never_shown" in crashed.path.read_text(encoding="utf-8")


# ===========================================================================
# Task 23: recovery transparency property
# ===========================================================================


def _uninterrupted_run(tmp_path: Path, run_id: str) -> Any:
    """Path A: an ordinary successful run, journalled."""
    path = tmp_path / f"{run_id}.jsonl"
    executor = FakeFileSearchExecutor()
    adapter = ScriptedModelAdapter(
        # Milestone 10: an uninterrupted run now ends on affirmative completion.
        (ModelResponse(structured_output=VALID_PROPOSAL), COMPLETION_RESPONSE)
    )
    context = RunContext(run_id=run_id)
    with RunJournal(path) as journal:
        outcome = asyncio.run(
            Controller(build_default_registry(executor), adapter, journal=journal).run(
                context, RECOVERY_MESSAGES
            )
        )
    return outcome, executor, adapter, path, context


def _authorization(path: Path) -> Any:
    """The one `ExecutionAuthorized` record on disk.

    Asserting the count is half the point: Milestone 10 contract I9 says a
    resume writes no second authorization, so a helper that quietly took the
    last of several would hide the invariant it is used to check.
    """
    found = [record for _, record in _records(path) if record.type == "execution_authorized"]
    assert len(found) == 1, f"expected exactly one authorization, found {len(found)}"
    return found[0]


def test_recovery_is_semantically_transparent(tmp_path: Path) -> None:
    """Recovery restores an execution; it does not re-decide one.

    Milestone 6 asserted this by comparing state traces, which worked while a
    run *was* one execution. Milestone 10 made a fresh run continue past
    RESPOND to ask for another, so trace equality now compares a composing run
    against a restoring one and fails for a reason that has nothing to do with
    transparency. The trace comparison moved to
    `test_recovery_manufactures_no_model_generation`, which asserts the
    difference deliberately; what remains here are the durable semantic facts,
    which is what M6 was really protecting.

    Note what is *not* asserted: that Path A's and Path B's execution ids are
    equal. They cannot be — `derive_execution_id` hashes the run id and these
    are two different runs. The identity claim recovery actually makes is
    internal to Path B: the execution it completes is the one authorized
    before the crash, byte for byte.
    """
    outcome_a, executor_a, adapter_a, path_a, _ = _uninterrupted_run(tmp_path / "a", "run-direct")

    crashed = crash_mid_execution(tmp_path / "b", run_id="run-recovered")
    # Read before the harness takes the lock: this is the authorization as it
    # stood at the interruption boundary, captured with nothing recovered yet.
    authorized = _authorization(crashed.path)

    harness = build_recovery_harness(crashed)
    recovered = harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    outcome_b = recovered.run
    assert outcome_b is not None
    # The harness holds the journal's exclusive lock; release it before
    # re-reading the file, exactly as the sibling journal tests do.
    harness.journal.close()
    settled = _authorization(crashed.path)

    # ---- 1. The exact authorized execution identity is reused (I8) --------
    assert recovered.execution_id == authorized.execution_id
    # And it is still a function of the operation, not a value carried along:
    # the completion record on disk names the same execution.
    completions = [r for _, r in _records(crashed.path) if r.type == "execution_completed"]
    assert [c.execution_id for c in completions] == [authorized.execution_id]

    # ---- 2. Step identity is reused, not reassigned (I8, I11) -------------
    # A recovered -s1 stays -s1. Were recovery to treat the restored execution
    # as a new one it would become -s2 here, and the run would silently have
    # consumed a second execution slot for the same work.
    assert authorized.step_id == f"{crashed.run_id}-s1"
    assert settled.step_id == authorized.step_id

    # ---- 3. The proposal is reused verbatim ------------------------------
    # The journal carries the *canonical* argument set — what the tool's schema
    # produced, defaults included — because that is the form the execution id
    # hashes and the form recovery re-validates. So the model's fields are a
    # subset of it, not equal to it, and asserting equality here would be
    # asserting that validation does nothing.
    proposed = json.loads(VALID_PROPOSAL)
    assert authorized.tool == proposed["tool"]
    assert proposed["arguments"].items() <= authorized.arguments.items()
    # Nothing re-authorized it under different terms.
    assert settled.arguments == authorized.arguments
    assert settled.capability_digest == authorized.capability_digest
    assert settled.side_effect_free == authorized.side_effect_free

    # ---- 4. Attempt semantics: restored, never advanced (I3) -------------
    assert authorized.attempt == 1
    assert outcome_b.attempts == authorized.attempt
    assert outcome_b.terminal.attempts == authorized.attempt

    # ---- 5. Recovery authorized nothing new (I9) -------------------------
    # `_authorization` already refuses a second record; state it as the
    # invariant too, so the reason this matters is on the page.
    assert _types(crashed.path).count("execution_authorized") == 1

    # ---- 6. Executor behaviour -------------------------------------------
    # One physical execution before the crash, one after recovery — and the
    # crash window is exactly why that is two rather than one. The number that
    # would signal a broken resume is a *third*.
    assert crashed.physical_executions == 1
    assert harness.executor.call_count == 1
    assert executor_a.call_count == 1

    # ---- 7. The durable execution result and terminal disposition --------
    assert outcome_a.result is not None and outcome_b.result is not None
    assert outcome_a.result.model_dump(mode="json") == outcome_b.result.model_dump(mode="json")
    assert outcome_a.terminal.model_dump(mode="json") == outcome_b.terminal.model_dump(mode="json")
    assert _types(path_a)[-1] == "run_terminal"
    assert _types(crashed.path)[-1] == "run_terminal"
    assert outcome_a.executions == outcome_b.executions == 1

    # ---- 8. The model learned nothing from any of it ----------------------
    assert adapter_a.call_count == 2  # the proposal, then the completion
    assert harness.adapter.call_count == 0  # the proposal came from the journal


def test_recovery_manufactures_no_model_generation(tmp_path: Path) -> None:
    """Both sides of the Milestone 10 boundary, asserted against each other.

    This is the assertion that replaced state-trace equality, and it is
    stronger rather than weaker: equality could hold while *both* runs
    composed, or while both stopped. This names which does which.

    The semantic claim is contract §1 and §7.5. A fresh run, having verified an
    execution, asks the model whether more work is wanted — an orchestration
    decision. A recovered run makes no such decision, because the model that
    produced the original proposal never saw the interruption and holds none of
    the context a post-recovery "what next?" turn would pretend it holds.
    """
    outcome_a, _, adapter_a, _, _ = _uninterrupted_run(tmp_path / "a", "run-direct")

    crashed = crash_mid_execution(tmp_path / "b", run_id="run-recovered")
    harness = build_recovery_harness(crashed)
    outcome_b = harness.recover(harness.decide("resume", "verified_safe_to_repeat")).run
    assert outcome_b is not None

    fresh = [s.value for s in outcome_a.states]
    resumed = [s.value for s in outcome_b.states]

    # FRESH RUN: composition remains available. RESPOND is followed by
    # GENERATE, and the run ends only because the model then said so.
    assert fresh[fresh.index("RESPOND") :] == ["RESPOND", "GENERATE", "PARSE", "TERMINAL"]
    assert fresh.count("GENERATE") == 2

    # RECOVERED RUN: the restored execution completes and the run stops.
    assert resumed[resumed.index("RESPOND") :] == ["RESPOND", "TERMINAL"]
    # Exactly one GENERATE, and it precedes the restored execution rather than
    # following it. That single entry is not a model call: `_loop` seeded from
    # the journal makes none, which the adapter count below proves. It is
    # recorded because the run really did pass through GENERATE before it
    # crashed — the same run continuing, not a new one skipping gates.
    assert resumed.count("GENERATE") == 1
    assert resumed.index("GENERATE") < resumed.index("PARSE")

    # The invariant stated directly rather than inferred from the trace: no
    # model generation follows the recovered execution.
    assert harness.adapter.call_count == 0
    assert adapter_a.call_count == 2

    # And the boundary is a difference in *composition*, not in outcome: the
    # two runs still agree on everything in the transparency test above.
    assert outcome_a.terminal.model_dump(mode="json") == outcome_b.terminal.model_dump(mode="json")


def test_the_recovered_journal_differs_only_by_its_audit_records(tmp_path: Path) -> None:
    """The permitted difference, stated explicitly rather than left implicit."""
    _, _, _, path_a, _context = _uninterrupted_run(tmp_path / "a", "run-direct")
    crashed = crash_mid_execution(tmp_path / "b", run_id="run-recovered")
    harness = build_recovery_harness(crashed)
    harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    harness.journal.close()

    direct = _types(path_a)
    recovered = _types(crashed.path)
    assert direct == ("run_started", "execution_authorized", "execution_completed", "run_terminal")
    assert recovered == (
        "run_started",
        "execution_authorized",
        "operator_decision",
        "execution_completed",
        "run_terminal",
    )
    assert tuple(t for t in recovered if t != "operator_decision") == direct


def test_replay_of_a_recovered_run_still_executes_nothing(tmp_path: Path) -> None:
    """The Milestone 5 property survives the new record type."""
    harness = _harness(tmp_path)
    harness.recover(harness.decide("resume", "verified_safe_to_repeat"))
    harness.journal.close()

    spy = FakeFileSearchExecutor()
    registry = build_default_registry(spy)
    records = _records(harness.journal.path)
    trace = replay(records, registry, harness.run_context)

    assert spy.call_count == 0
    assert trace.operator_actions == ("resume",)
    assert trace.terminal_status == "succeeded"
    assert plan_recovery(records, registry, harness.run_context).is_terminal is True
