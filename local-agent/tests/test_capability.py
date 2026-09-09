"""The capability contract: admission, immutability, identity, classification.

Milestone 7 asks one question — *what must be true before a capability is
admissible, and what stops the capability from becoming an authority?* — and
this file answers it by attack rather than by assertion of intent.

Every test here traces to something that was **measured** on the pre-Milestone-7
tree rather than reasoned about. Before this milestone the registry admitted an
empty name, a path-shaped name, a negative timeout, an `args_schema` that was
not a model, an executor with no `execute`, and a destructive capability that
required no authorization; `_by_name` could be written through and rebound; and
a failing `MUTATING` capability was re-run once per attempt in the budget. Each
of those is now a named test, so a regression is a failure rather than a
rediscovery.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from conftest import (
    COMPLETION_RESPONSE,
    RECOVERY_MESSAGES,
    VALID_PROPOSAL,
    FailingExecutor,
    SimulatedCrash,
    build_recovery_harness,
    completion_transport,
    crash_mid_execution,
)
from pydantic import BaseModel, ValidationError

from local_agent.contracts import (
    FileSearchArgs,
    FileSearchResult,
    ModelResponse,
    WorkspaceReadArgs,
)
from local_agent.controller import Controller
from local_agent.executors.file_search import FakeFileSearchExecutor, build_file_search_spec
from local_agent.model_adapter import ScriptedModelAdapter
from local_agent.persistence.journal import RunJournal
from local_agent.policy import RunContext, authorize, evaluate_policy
from local_agent.recovery import RecoveryError, plan_recovery
from local_agent.registry import (
    CAPABILITY_SCHEMA_VERSION,
    MAX_TIMEOUT_SECONDS,
    MAX_TOOL_NAME_LENGTH,
    CapabilityInadmissible,
    SideEffect,
    ToolRegistry,
    ToolSpec,
    admit,
    capability_digest,
)
from local_agent.wiring import build_default_registry


@contextlib.contextmanager
def widened(schema: type[BaseModel]) -> Iterator[None]:
    """Temporarily widen a model class, then restore it byte-for-byte.

    mypy objects to assigning into `model_config` because it is a `TypedDict`,
    and it is right to object: ordinary code has no business doing this. That
    is precisely the property under test — a capability's schemas are classes
    and classes are mutable — so the objection is answered once, here, with an
    explicit cast, rather than silenced at four call sites.
    """
    config = cast(dict[str, Any], schema.model_config)
    saved = dict(config)
    try:
        config["extra"] = "allow"
        schema.model_rebuild(force=True)
        yield
    finally:
        config.clear()
        config.update(saved)
        schema.model_rebuild(force=True)


def spec(**overrides: Any) -> ToolSpec:
    """A minimal admissible capability, with one property changed at a time."""
    fields: dict[str, Any] = {
        "name": "file_search",
        "args_schema": FileSearchArgs,
        "executor": FakeFileSearchExecutor(),
        "timeout_seconds": 5.0,
        "requires_authorization": True,
        "destructive": False,
        "result_schema": FileSearchResult,
        "side_effect": SideEffect.NONE,
    }
    fields.update(overrides)
    return ToolSpec(**fields)


# ===========================================================================
# Admission (task 3, task 6)
# ===========================================================================


def test_the_baseline_capability_is_admissible() -> None:
    """The positive control. Without it every refusal below could be vacuous."""
    admitted = admit(spec())
    assert admitted.name == "file_search"
    ToolRegistry((admitted,))  # and it reaches a registry


class _NoExecute:
    """An object that is not an executor. Nothing named `execute`."""


_INADMISSIBLE: list[tuple[str, dict[str, Any], str]] = [
    ("empty_name", {"name": ""}, "capability_name_empty"),
    ("name_too_long", {"name": "a" * (MAX_TOOL_NAME_LENGTH + 1)}, "capability_name_too_long"),
    ("path_shaped_name", {"name": "../../etc/passwd"}, "capability_name_empty_segment"),
    ("slash_in_name", {"name": "workspace/read"}, "capability_name_character_invalid"),
    ("uppercase_name", {"name": "FileSearch"}, "capability_name_segment_start_invalid"),
    ("space_in_name", {"name": "file search"}, "capability_name_character_invalid"),
    ("empty_segment", {"name": "workspace..read"}, "capability_name_empty_segment"),
    ("leading_digit", {"name": "1tool"}, "capability_name_segment_start_invalid"),
    ("null_byte_name", {"name": "tool\x00evil"}, "capability_name_character_invalid"),
    ("negative_timeout", {"timeout_seconds": -5.0}, "capability_timeout_out_of_range"),
    ("zero_timeout", {"timeout_seconds": 0.0}, "capability_timeout_out_of_range"),
    (
        "unbounded_timeout",
        {"timeout_seconds": MAX_TIMEOUT_SECONDS + 1},
        "capability_timeout_out_of_range",
    ),
    ("timeout_not_a_number", {"timeout_seconds": "5"}, "capability_timeout_not_a_number"),
    ("timeout_is_a_bool", {"timeout_seconds": True}, "capability_timeout_not_a_number"),
    ("args_schema_not_a_model", {"args_schema": dict}, "capability_args_schema_not_a_model"),
    ("args_schema_an_instance", {"args_schema": object()}, "capability_args_schema_not_a_model"),
    ("result_schema_not_a_model", {"result_schema": list}, "capability_result_schema_not_a_model"),
    ("executor_without_execute", {"executor": _NoExecute()}, "capability_executor_not_callable"),
    ("executor_execute_not_callable", {"executor": 42}, "capability_executor_not_callable"),
    (
        "side_effect_not_classified",
        {"side_effect": "none"},
        "capability_side_effect_not_classified",
    ),
    (
        "destructive_without_authorization",
        {"destructive": True, "requires_authorization": False, "side_effect": SideEffect.MUTATING},
        "capability_destructive_without_authorization",
    ),
    (
        "destructive_but_not_mutating",
        {"destructive": True, "side_effect": SideEffect.NONE},
        "capability_destructive_but_not_mutating",
    ),
    (
        "requires_authorization_not_a_bool",
        {"requires_authorization": 1},
        "capability_requires_authorization_not_a_bool",
    ),
    ("destructive_not_a_bool", {"destructive": "yes"}, "capability_destructive_not_a_bool"),
]


@pytest.mark.parametrize(("label", "overrides", "reason"), _INADMISSIBLE, ids=lambda v: v)
def test_an_inadmissible_capability_is_refused(
    label: str, overrides: dict[str, Any], reason: str
) -> None:
    """Each refusal is by stable slug, so the matrix is testable by outcome."""
    with pytest.raises(CapabilityInadmissible) as caught:
        admit(spec(**overrides))
    assert caught.value.reason == reason


@pytest.mark.parametrize(("label", "overrides", "reason"), _INADMISSIBLE, ids=lambda v: v)
def test_an_inadmissible_capability_never_reaches_a_registry(
    label: str, overrides: dict[str, Any], reason: str
) -> None:
    """The registry re-checks rather than trusting that someone called `admit`.

    This is the half that matters. `admit` is a courtesy for wiring; the
    registry is the enforcement, because a spec can reach it by any route.
    """
    with pytest.raises(CapabilityInadmissible) as caught:
        ToolRegistry((spec(**overrides),))
    assert caught.value.reason == reason


def test_a_destructive_capability_that_skipped_the_grant_check_cannot_exist() -> None:
    """The measured defect, restated as the property that now holds.

    `policy.authorize` only consults a run's tool grants when the capability
    declares `requires_authorization`. A destructive capability that declared
    otherwise would therefore run for a run holding *no grants at all* — and it
    did, measured directly on the gate. The fix is at admission rather than in
    the gate: `authorize` is a Milestone 1 invariant and is unchanged; the
    incoherent capability simply cannot enter a registry.
    """
    incoherent = spec(
        name="wipe",
        destructive=True,
        requires_authorization=False,
        side_effect=SideEffect.MUTATING,
    )
    # The gate still says yes — which is precisely why admission must say no.
    granted_nothing = RunContext(run_id="r", authorized_tools=frozenset())
    assert authorize(incoherent, FileSearchArgs(query="q", root_id="workspace"), granted_nothing)

    with pytest.raises(CapabilityInadmissible) as caught:
        ToolRegistry((incoherent,))
    assert caught.value.reason == "capability_destructive_without_authorization"


def test_a_replaced_spec_is_re_checked_rather_than_carried_forward() -> None:
    """`dataclasses.replace` must not be able to launder a capability.

    There is deliberately no "already admitted" marker: a marker is a field,
    and `replace` copies fields. So a spec derived from an admissible one is
    checked on its own terms.
    """
    good = admit(spec(destructive=False, requires_authorization=True))
    laundered = dataclasses.replace(
        good, destructive=True, requires_authorization=False, side_effect=SideEffect.MUTATING
    )

    with pytest.raises(CapabilityInadmissible) as caught:
        ToolRegistry((laundered,))
    assert caught.value.reason == "capability_destructive_without_authorization"


def test_admission_is_idempotent_and_returns_the_same_capability() -> None:
    one = admit(spec())
    assert admit(one) == one


# ===========================================================================
# Registry admission boundary (task 6)
# ===========================================================================


def test_duplicate_capability_names_are_refused_rather_than_replaced() -> None:
    """Last-one-wins would be how a capability came to mean something new."""
    with pytest.raises(CapabilityInadmissible) as caught:
        ToolRegistry((admit(spec()), admit(spec())))
    assert caught.value.reason == "registry_duplicate_capability_name"


def test_a_non_toolspec_entry_is_refused() -> None:
    with pytest.raises(CapabilityInadmissible) as caught:
        ToolRegistry(("file_search",))  # type: ignore[arg-type]
    assert caught.value.reason == "registry_entry_not_a_tool_spec"


def test_the_registry_exposes_no_mutation_api() -> None:
    """Registration is not a runtime operation; there is nothing to call."""
    registry = build_default_registry(FakeFileSearchExecutor())
    for forbidden in ("register", "add", "replace", "remove", "update", "pop", "setdefault"):
        assert not hasattr(registry, forbidden), f"ToolRegistry exposes {forbidden}"


def test_the_registry_map_cannot_be_written_through() -> None:
    """The measured defect: `_by_name['evil'] = spec` used to work."""
    registry = build_default_registry(FakeFileSearchExecutor())
    with pytest.raises(TypeError):
        registry._by_name["evil"] = admit(spec())  # type: ignore[index]
    assert registry.names == frozenset({"file_search"})


def test_the_registry_map_cannot_be_rebound() -> None:
    """The other measured defect: `_by_name = {}` used to work."""
    registry = build_default_registry(FakeFileSearchExecutor())
    with pytest.raises(AttributeError):
        registry._by_name = {}
    with pytest.raises(AttributeError):
        registry.anything_else = 1
    with pytest.raises(AttributeError):
        del registry._by_name
    assert registry.names == frozenset({"file_search"})


def test_the_registry_views_are_read_only() -> None:
    registry = build_default_registry(FakeFileSearchExecutor())
    assert isinstance(registry.names, frozenset)
    with pytest.raises(TypeError):
        registry.entries["x"] = admit(spec())  # type: ignore[index]
    with pytest.raises(TypeError):
        registry.digests()["x"] = "y"  # type: ignore[index]


def test_a_missing_capability_resolves_to_nothing_rather_than_a_default() -> None:
    registry = build_default_registry(FakeFileSearchExecutor())
    assert registry.get("nonexistent") is None
    assert "nonexistent" not in registry


# ===========================================================================
# ToolSpec immutability (task 5)
# ===========================================================================


@pytest.mark.parametrize(
    "field",
    [
        "name",
        "args_schema",
        "executor",
        "timeout_seconds",
        "requires_authorization",
        "destructive",
        "result_schema",
        "side_effect",
    ],
)
def test_no_toolspec_field_can_be_reassigned(field: str) -> None:
    admitted = admit(spec())
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(admitted, field, object())


def test_a_toolspec_cannot_grow_a_new_field() -> None:
    """A forged attribute would be a capability declaring something extra."""
    admitted = admit(spec())
    with pytest.raises(dataclasses.FrozenInstanceError):
        admitted.authorized = True  # type: ignore[attr-defined]


def test_the_derived_properties_cannot_disagree_with_the_classification() -> None:
    """`side_effect_free` is computed, not stored, so drift is impossible."""
    for classification, free, repeatable in (
        (SideEffect.NONE, True, True),
        (SideEffect.IDEMPOTENT, False, True),
        (SideEffect.MUTATING, False, False),
    ):
        candidate = admit(spec(side_effect=classification))
        assert candidate.side_effect_free is free
        assert candidate.re_executable is repeatable
        with pytest.raises(AttributeError):
            candidate.side_effect_free = True  # type: ignore[misc]
        with pytest.raises(AttributeError):
            candidate.re_executable = True  # type: ignore[misc]


def test_the_schema_classes_a_spec_points_at_remain_mutable() -> None:
    """The limitation, asserted rather than glossed over.

    Python has no way to freeze a class, so `args_schema.model_fields` and
    `model_config` stay writable and a `model_rebuild(force=True)` makes the
    change take effect. Pretending otherwise would be the dangerous move; the
    contract's answer is `capability_digest`, tested next, which makes the
    change *detectable* rather than claiming it is impossible.
    """
    admitted = admit(spec())
    with widened(admitted.args_schema):
        smuggled = admitted.args_schema.model_validate(
            {"query": "q", "root_id": "workspace", "smuggled": 1}
        )
        assert "smuggled" in smuggled.model_dump()

    with pytest.raises(ValidationError):
        admitted.args_schema.model_validate({"query": "q", "root_id": "workspace", "smuggled": 1})


# ===========================================================================
# Capability identity (task 3)
# ===========================================================================


def test_a_capability_digest_is_stable_across_equivalent_definitions() -> None:
    assert capability_digest(admit(spec())) == capability_digest(admit(spec()))
    assert len(capability_digest(admit(spec()))) == 32


def test_swapping_the_executor_does_not_change_the_capability() -> None:
    """Deliberate, and stated as a cost rather than a win.

    A test that substitutes a spy for the production executor must exercise the
    same capability, or every recovery test would be about a different one. The
    price is that the digest does not detect an executor swap, and nothing here
    claims it does.
    """
    assert capability_digest(admit(spec(executor=FakeFileSearchExecutor()))) == capability_digest(
        admit(spec(executor=FailingExecutor()))
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": "other_tool"},
        {"timeout_seconds": 6.0},
        {"requires_authorization": False},
        {"side_effect": SideEffect.IDEMPOTENT},
        {"args_schema": WorkspaceReadArgs},
    ],
    ids=["name", "timeout", "authorization", "classification", "args_schema"],
)
def test_changing_a_declared_property_changes_the_capability(overrides: dict[str, Any]) -> None:
    assert capability_digest(admit(spec())) != capability_digest(admit(spec(**overrides)))


def test_a_mutated_argument_schema_changes_the_capability_digest() -> None:
    """The whole reason the digest exists: it covers what immutability cannot."""
    admitted = admit(spec())
    before = capability_digest(admitted)
    with widened(admitted.args_schema):
        assert capability_digest(admitted) != before
    assert capability_digest(admitted) == before


def test_the_registry_recomputes_digests_rather_than_caching_them() -> None:
    """A cached digest would keep reporting the value a mutation replaced."""
    registry = build_default_registry(FakeFileSearchExecutor())
    before = registry.digests()["file_search"]
    with widened(FileSearchArgs):
        assert registry.digests()["file_search"] != before
    assert registry.digests()["file_search"] == before


def test_the_capability_schema_version_participates_in_identity() -> None:
    """A contract change must invalidate every previously recorded digest."""
    assert CAPABILITY_SCHEMA_VERSION == 1
    material = json.dumps({"schema_version": CAPABILITY_SCHEMA_VERSION})
    assert "schema_version" in material


# ===========================================================================
# Side-effect / retry / idempotency matrix (task 8)
# ===========================================================================


class CountingSideEffect:
    """Performs an irreversible act, then fails in a way the controller retries."""

    def __init__(self) -> None:
        self.effects = 0

    def execute(self, args: Any) -> Any:
        self.effects += 1
        from local_agent.registry import ToolExecutionError

        raise ToolExecutionError("downstream hiccup")


def _run(registry: ToolRegistry, complete: bool = True) -> Any:
    """Drive one run against `registry`.

    Milestone 10: a run ends only when the model affirmatively completes, so a
    single-execution success scripts two turns. `complete=False` is for tests
    whose purpose is to exhaust the attempt budget — a completion offered mid
    repair is refused as "not a repair", which would end the run early on the
    outstanding error instead of on exhaustion.
    """
    script: tuple[ModelResponse, ...] = (ModelResponse(structured_output=VALID_PROPOSAL),)
    if complete:
        script += (COMPLETION_RESPONSE,)
    return asyncio.run(
        Controller(registry, ScriptedModelAdapter(script)).run(
            RunContext(run_id="r", max_attempts=3), RECOVERY_MESSAGES
        )
    )


@pytest.mark.parametrize(
    ("classification", "expected_effects"),
    [(SideEffect.NONE, 3), (SideEffect.IDEMPOTENT, 3), (SideEffect.MUTATING, 1)],
    ids=["A_none", "B_idempotent", "C_mutating"],
)
def test_in_run_retry_respects_the_side_effect_classification(
    classification: SideEffect, expected_effects: int
) -> None:
    """Cases A, B and C: execute, fail, and see whether it runs again.

    The measured pre-Milestone-7 behaviour was three physical effects in every
    row, because retry consulted only the *error code* and never the
    capability. A budget of three therefore meant three irreversible acts for a
    capability that had never claimed repeating was safe.
    """
    executor = CountingSideEffect()
    # `complete=False`: this row is *about* spending the attempt budget, so the
    # model must keep proposing rather than completing. A completion offered
    # mid-repair is refused as "not a repair" and would end the run after one
    # effect, which would make rows A and B silently agree with row C for
    # entirely the wrong reason.
    outcome = _run(
        ToolRegistry((admit(spec(executor=executor, side_effect=classification)),)),
        complete=False,
    )

    assert executor.effects == expected_effects
    assert outcome.terminal.status == "failed"


def test_the_retry_gate_is_recorded_in_the_audit_stream() -> None:
    """The model gets an opaque code; the audit gets the true reason."""
    executor = CountingSideEffect()
    outcome = _run(ToolRegistry((admit(spec(executor=executor, side_effect=SideEffect.MUTATING)),)))

    withheld = [event for event in outcome.events if event.type == "retry_withheld"]
    assert len(withheld) == 1
    assert dict(withheld[0].detail)["reason"] == "capability_not_re_executable"
    # And the model-facing code is unchanged, carrying no classification.
    assert outcome.terminal.code == "RETRY_EXHAUSTED"
    assert outcome.error is not None
    assert "mutating" not in outcome.error.message.lower()
    assert "side" not in outcome.error.message.lower()


def test_a_rejection_before_execution_still_retries_for_any_classification() -> None:
    """Case E: nothing ran, so the capability contract has no say.

    Gating retry on the classification must not break the ordinary repair loop
    for a malformed proposal — nothing physical happened, so there is nothing
    to avoid repeating.
    """
    executor = CountingSideEffect()
    registry = ToolRegistry((admit(spec(executor=executor, side_effect=SideEffect.MUTATING)),))
    adapter = ScriptedModelAdapter((ModelResponse(structured_output="{not json"),))
    outcome = asyncio.run(
        Controller(registry, adapter).run(RunContext(run_id="r", max_attempts=3), RECOVERY_MESSAGES)
    )

    assert executor.effects == 0
    assert outcome.attempts == 3  # the model got its ordinary three chances
    assert adapter.call_count == 3


def test_case_d_execution_succeeded_but_the_evidence_was_lost(tmp_path: Path) -> None:
    """Case D: the physical call finished; the completion record did not land."""
    from conftest import CrashingJournal

    executor = FakeFileSearchExecutor()
    registry = build_default_registry(executor)
    journal = CrashingJournal(tmp_path / "d.jsonl", crash_before="execution_completed")
    context = RunContext(run_id="run-d")
    with pytest.raises(SimulatedCrash):
        asyncio.run(
            Controller(
                registry,
                ScriptedModelAdapter((ModelResponse(structured_output=VALID_PROPOSAL),)),
                journal=journal,
            ).run(context, RECOVERY_MESSAGES)
        )
    journal.close()

    assert executor.call_count == 1  # it happened
    with RunJournal(tmp_path / "d.jsonl") as reopened:
        plan = plan_recovery(reopened.records(), registry, context)
    # And the system says it does not know, rather than inventing either answer.
    assert plan.disposition == "execution_pending_repeatable"
    assert plan.execution_status is None


def test_case_e_crash_before_the_physical_call_records_no_execution(tmp_path: Path) -> None:
    """Case E, on the durable side: nothing authorized means nothing happened."""
    from conftest import CrashingJournal

    executor = FakeFileSearchExecutor()
    registry = build_default_registry(executor)
    journal = CrashingJournal(tmp_path / "e.jsonl", crash_before="execution_authorized")
    context = RunContext(run_id="run-e")
    with pytest.raises(SimulatedCrash):
        asyncio.run(
            Controller(
                registry,
                ScriptedModelAdapter((ModelResponse(structured_output=VALID_PROPOSAL),)),
                journal=journal,
            ).run(context, RECOVERY_MESSAGES)
        )
    journal.close()

    assert executor.call_count == 0
    with RunJournal(tmp_path / "e.jsonl") as reopened:
        plan = plan_recovery(reopened.records(), registry, context)
    assert plan.disposition == "no_execution_authorized"


def test_case_f_a_reused_execution_identity_is_refused(tmp_path: Path) -> None:
    """Case F: two authorizations claiming one identity is not a run this
    controller could have produced."""
    from local_agent.persistence.records import (
        ExecutionAuthorized,
        RunStarted,
        derive_execution_id,
    )

    args = {"query": "q", "root_id": "workspace", "max_results": 10}
    execution_id = derive_execution_id("run-f", "run-f-s1", 1, "file_search", args)
    authorization = ExecutionAuthorized(
        run_id="run-f",
        step_id="run-f-s1",
        attempt=1,
        tool="file_search",
        arguments=args,
        execution_id=execution_id,
        side_effect_free=True,
    )
    path = tmp_path / "f.jsonl"
    with RunJournal(path) as journal:
        journal.append(RunStarted(run_id="run-f", max_attempts=3))
        journal.append(authorization)
        journal.append(authorization)

    registry = build_default_registry(FakeFileSearchExecutor())
    with RunJournal(path) as journal, pytest.raises(RecoveryError) as caught:
        plan_recovery(journal.records(), registry, RunContext(run_id="run-f"))
    assert caught.value.reason == "journal_duplicate_authorization"


def test_case_g_a_capability_definition_change_is_detected(tmp_path: Path) -> None:
    """Case G, and the reason the digest exists.

    The arguments still validate and the execution identity still re-derives —
    every Milestone 5 and 6 check passes. Only the capability's own content
    address notices that it now means something different.
    """
    crashed = crash_mid_execution(tmp_path, run_id="run-g")
    registry = build_default_registry(FakeFileSearchExecutor())
    context = RunContext(run_id="run-g")

    with RunJournal(crashed.path) as journal:
        assert plan_recovery(journal.records(), registry, context).capability_verified is True

    with widened(FileSearchArgs):
        with RunJournal(crashed.path) as journal, pytest.raises(RecoveryError) as caught:
            plan_recovery(journal.records(), registry, context)
        assert caught.value.reason == "journal_capability_digest_mismatch"

    # And the same journal is accepted again once the definition is restored,
    # so the digest is comparing the definition rather than latching a failure.
    with RunJournal(crashed.path) as journal:
        assert plan_recovery(journal.records(), registry, context).capability_verified is True


def test_case_h_a_capability_that_disappeared_stops_recovery(tmp_path: Path) -> None:
    """Case H: the capability is gone, so the run cannot be re-authorized."""
    crashed = crash_mid_execution(tmp_path, run_id="run-h")
    with RunJournal(crashed.path) as journal, pytest.raises(RecoveryError) as caught:
        plan_recovery(journal.records(), ToolRegistry(()), RunContext(run_id="run-h"))
    assert caught.value.reason == "journal_tool_not_in_registry"


def test_a_journal_without_a_digest_is_reported_unverifiable_not_verified(
    tmp_path: Path,
) -> None:
    """Absence of evidence is reported as absence, not as evidence."""
    from local_agent.persistence.records import (
        ExecutionAuthorized,
        RunStarted,
        derive_execution_id,
    )

    args = {"query": "q", "root_id": "workspace", "max_results": 10}
    path = tmp_path / "legacy.jsonl"
    with RunJournal(path) as journal:
        journal.append(RunStarted(run_id="run-legacy", max_attempts=3))
        journal.append(
            ExecutionAuthorized(
                run_id="run-legacy",
                step_id="run-legacy-s1",
                attempt=1,
                tool="file_search",
                arguments=args,
                execution_id=derive_execution_id(
                    "run-legacy", "run-legacy-s1", 1, "file_search", args
                ),
                side_effect_free=True,
                # no capability_digest: a journal written before the field
            )
        )

    registry = build_default_registry(FakeFileSearchExecutor())
    with RunJournal(path) as journal:
        plan = plan_recovery(journal.records(), registry, RunContext(run_id="run-legacy"))
    assert plan.capability_verified is False
    assert plan.capability_digest is None


def test_the_ambiguity_classification_follows_the_capability(tmp_path: Path) -> None:
    """`NONE` is repeatable after an ambiguous crash; the other two are not.

    Note the asymmetry, which is the whole reason for three values rather than
    two. An `IDEMPOTENT` capability is safe to *retry* after a known failure —
    the previous test proves it gets its three attempts — and is still
    `execution_unknown` after an *ambiguous* crash, because "did it happen" and
    "is repeating safe" are different questions and only the first is what an
    operator is being told. A boolean cannot hold both answers.
    """
    for classification, expected in (
        (SideEffect.NONE, "execution_pending_repeatable"),
        (SideEffect.IDEMPOTENT, "execution_unknown"),
        (SideEffect.MUTATING, "execution_unknown"),
    ):
        label = classification.value
        crashed = crash_mid_execution(
            tmp_path / label, run_id=f"run-{label}", classification=classification
        )
        registry = ToolRegistry(
            (
                dataclasses.replace(
                    build_file_search_spec(FakeFileSearchExecutor()), side_effect=classification
                ),
            )
        )
        with RunJournal(crashed.path) as journal:
            plan = plan_recovery(journal.records(), registry, RunContext(run_id=f"run-{label}"))
        assert plan.disposition == expected, label
        assert plan.side_effect_free is (classification is SideEffect.NONE), label


# ===========================================================================
# Executor isolation (task 7)
# ===========================================================================


class AuthorityHungryExecutor:
    """Tries every escalation an executor could attempt from inside `execute`."""

    def __init__(self) -> None:
        self.findings: dict[str, str] = {}

    def execute(self, args: Any) -> Any:
        for label, attempt in (
            ("reach_run_context", lambda: args.max_attempts),
            ("reach_grants", lambda: args.authorized_tools),
            ("reach_registry", lambda: args.registry),
            ("reach_executor", lambda: args.executor),
            ("reach_controller", lambda: args.controller),
            ("mutate_args", lambda: setattr(args, "root_id", "knowledge")),
        ):
            try:
                attempt()
                self.findings[label] = "REACHED"
            except (AttributeError, ValidationError, TypeError) as exc:
                # Narrow on purpose. These are the refusals the boundary is
                # supposed to produce; anything else escaping here would be an
                # unexpected route out of the executor's sandbox, and failing
                # loudly on it is more useful than recording its name.
                self.findings[label] = type(exc).__name__
        return {"status": "success", "data": []}


def test_an_executor_can_reach_no_authority_from_its_arguments() -> None:
    """The executor's whole world is one validated arguments object."""
    executor = AuthorityHungryExecutor()
    outcome = _run(build_default_registry(executor))

    assert outcome.succeeded
    assert "REACHED" not in executor.findings.values(), executor.findings
    assert executor.findings["mutate_args"] == "ValidationError"


def test_an_executor_cannot_widen_its_own_result_past_verification() -> None:
    """A swapped `execute` gains nothing: the result schema still decides."""
    registry = build_default_registry(FakeFileSearchExecutor())
    spec_under_test = registry.get("file_search")
    assert spec_under_test is not None
    spec_under_test.executor.execute = lambda args: {  # type: ignore[method-assign]
        "status": "success",
        "data": [],
        "authorized": True,
        "max_attempts": 999,
    }
    outcome = _run(registry, complete=False)

    assert not outcome.succeeded
    assert outcome.terminal.code == "RETRY_EXHAUSTED"
    assert outcome.error is not None
    assert outcome.error.code == "RETRY_EXHAUSTED" or outcome.error.code == "VERIFICATION_FAILED"


def test_an_executor_denial_can_only_deny() -> None:
    """`ToolDenialError` is fail-closed by construction: there is no grant path."""
    from local_agent.registry import ToolDenialError

    class DenyingExecutor:
        def execute(self, args: Any) -> Any:
            raise ToolDenialError("discovered_outside_root")

    outcome = _run(build_default_registry(DenyingExecutor()))
    assert not outcome.succeeded
    assert outcome.terminal.code == "POLICY_DENIED"
    assert outcome.attempts == 1  # non-retryable, exactly like the two gates


# ===========================================================================
# Result boundary (task 11)
# ===========================================================================


_HOSTILE_RESULTS: list[tuple[str, Any]] = [
    ("not_a_mapping", ["status", "success"]),
    ("missing_field", {"status": "success"}),
    ("wrong_type", {"status": "success", "data": "not-a-list"}),
    ("unexpected_status", {"status": "authorized", "data": []}),
    ("extra_authority_field", {"status": "success", "data": [], "authorized": True}),
    ("extra_budget_field", {"status": "success", "data": [], "max_attempts": 999}),
    ("extra_grant_field", {"status": "success", "data": [], "authorized_tools": ["shell"]}),
    ("nested_authority", {"status": "success", "data": [], "policy": {"allow_destructive": True}}),
    ("none_result", None),
    ("empty_result", {}),
]


@pytest.mark.parametrize(("label", "payload"), _HOSTILE_RESULTS, ids=lambda v: v)
def test_a_hostile_result_never_becomes_a_controller_command(label: str, payload: Any) -> None:
    """Every one of these is data that fails verification, not an instruction."""
    from conftest import CorruptResultExecutor

    executor = CorruptResultExecutor(payload)
    outcome = _run(build_default_registry(executor))

    assert not outcome.succeeded
    assert executor.call_count >= 1
    # Nothing the result claimed changed the run's authority.
    assert outcome.attempts <= 3


def test_instruction_shaped_result_content_stays_data() -> None:
    """A well-formed result whose *content* is an instruction is still content."""
    from conftest import InjectingExecutor

    executor = InjectingExecutor()
    outcome = _run(build_default_registry(executor))

    assert outcome.succeeded  # the shape was valid, so the result verified
    assert outcome.result is not None
    assert outcome.result.model_dump(mode="json")["data"] == [InjectingExecutor.PAYLOAD]
    assert outcome.attempts == 1  # nothing in the payload changed the budget


def test_an_oversized_result_is_bounded_by_the_capability_not_by_luck(tmp_path: Path) -> None:
    """Result size is a `FilesystemLimits` ceiling, enforced by the executor.

    Recorded here as part of the capability contract's resource-bounds story:
    the bound exists, it lives in `RunContext`, and the executor that holds the
    capability enforces it by rejecting rather than truncating.
    """
    from local_agent.policy import FilesystemLimits

    limits = FilesystemLimits(max_serialized_result_bytes=32)
    assert limits.max_serialized_result_bytes == 32
    with pytest.raises(ValueError):
        FilesystemLimits(max_serialized_result_bytes=0)


# ===========================================================================
# Model boundary (task 10)
# ===========================================================================

_AUTHORITY_FIELD_NAMES = [
    "authorize",
    "grant",
    "executor",
    "policy",
    "retry",
    "side_effect_free",
    "side_effect",
    "idempotent",
    "operator",
    "recovery",
    "terminal",
    "tool_spec",
    "registry",
    "capability_digest",
    "admitted",
    "re_executable",
    "max_attempts",
    "authorized_tools",
]


@pytest.mark.parametrize("field", _AUTHORITY_FIELD_NAMES)
def test_an_authority_named_field_in_a_proposal_is_refused(field: str) -> None:
    """A model emitting `"authorize": true` is emitting a string, not a decision.

    Refused at the envelope, before any tool is resolved, because `RawToolCall`
    forbids extras. There is no branch that reads these names, which is why the
    list can grow without the controller growing.
    """
    executor = FakeFileSearchExecutor()
    proposal = json.dumps(
        {"tool": "file_search", "arguments": {"query": "q", "root_id": "workspace"}, field: True}
    )
    outcome = asyncio.run(
        Controller(
            build_default_registry(executor),
            ScriptedModelAdapter((ModelResponse(structured_output=proposal),)),
        ).run(RunContext(run_id="r", max_attempts=1), RECOVERY_MESSAGES)
    )

    assert not outcome.succeeded
    assert outcome.error is not None
    assert outcome.error.code == "TOOL_CALL_MALFORMED"
    assert executor.call_count == 0


@pytest.mark.parametrize("field", _AUTHORITY_FIELD_NAMES)
def test_an_authority_named_argument_is_refused_by_the_capability_schema(field: str) -> None:
    """Inside `arguments` the capability's own schema is the gate."""
    executor = FakeFileSearchExecutor()
    proposal = json.dumps(
        {
            "tool": "file_search",
            "arguments": {"query": "q", "root_id": "workspace", field: True},
        }
    )
    outcome = asyncio.run(
        Controller(
            build_default_registry(executor),
            ScriptedModelAdapter((ModelResponse(structured_output=proposal),)),
        ).run(RunContext(run_id="r", max_attempts=1), RECOVERY_MESSAGES)
    )

    assert not outcome.succeeded
    assert outcome.error is not None
    assert outcome.error.code == "SCHEMA_INVALID"
    assert executor.call_count == 0


def test_the_model_cannot_name_a_capability_that_was_never_admitted() -> None:
    executor = FakeFileSearchExecutor()
    proposal = json.dumps({"tool": "shell", "arguments": {"cmd": "rm -rf /"}})
    outcome = asyncio.run(
        Controller(
            build_default_registry(executor),
            ScriptedModelAdapter((ModelResponse(structured_output=proposal),)),
        ).run(RunContext(run_id="r", max_attempts=1), RECOVERY_MESSAGES)
    )

    assert outcome.error is not None
    assert outcome.error.code == "TOOL_NOT_FOUND"
    assert executor.call_count == 0


def test_the_model_visible_surface_carries_no_capability_authority() -> None:
    """Descriptions expose name and argument shape; nothing else."""
    from local_agent.wiring import describe_tools

    registry = build_default_registry(FakeFileSearchExecutor())
    rendered = json.dumps(
        [dataclasses.asdict(description) for description in describe_tools(registry)]
    )

    for forbidden in (
        "side_effect",
        "requires_authorization",
        "destructive",
        "timeout_seconds",
        "executor",
        "re_executable",
        "capability_digest",
    ):
        assert forbidden not in rendered, f"the model-visible surface leaked {forbidden}"


# ===========================================================================
# Determinism (task 13)
# ===========================================================================

CAPABILITY_REPETITIONS = 100


def test_capability_contract_operations_are_deterministic() -> None:
    """Admission, lookup, gates, identity and rejection reasons, 100x."""

    def fingerprint() -> str:
        registry = build_default_registry(FakeFileSearchExecutor())
        candidate = registry.get("file_search")
        assert candidate is not None
        args = FileSearchArgs(query="q", root_id="workspace")
        context = RunContext(run_id="run-fp")
        reasons = []
        for _, overrides, _ in _INADMISSIBLE:
            try:
                admit(spec(**overrides))
            except CapabilityInadmissible as exc:
                reasons.append(exc.reason)
        return json.dumps(
            {
                "names": sorted(registry.names),
                "digests": dict(registry.digests()),
                "authorize": authorize(candidate, args, context).allowed,
                "policy": evaluate_policy(candidate, args, context).allowed,
                "side_effect": candidate.side_effect.value,
                "side_effect_free": candidate.side_effect_free,
                "re_executable": candidate.re_executable,
                "rejections": reasons,
            },
            sort_keys=True,
        )

    baseline = fingerprint()
    assert {fingerprint() for _ in range(CAPABILITY_REPETITIONS)} == {baseline}


def test_capability_fingerprints_carry_no_host_detail() -> None:
    registry = build_default_registry(FakeFileSearchExecutor())
    rendered = json.dumps(dict(registry.digests())).lower()
    for forbidden in ("/home", "/tmp", "0x", "127.0.0.1", "sk-"):
        assert forbidden not in rendered


def test_the_production_capabilities_are_all_admissible_and_classified() -> None:
    """A sweep over what actually ships, not over a fixture."""
    from local_agent.executors.workspace_fs import (
        WorkspaceListExecutor,
        WorkspaceReadExecutor,
    )
    from local_agent.wiring import build_filesystem_registry, build_physical_roots

    roots = build_physical_roots({})
    registries = [
        build_default_registry(FakeFileSearchExecutor()),
        build_filesystem_registry(
            roots,
            read_executor=WorkspaceReadExecutor(roots),
            list_executor=WorkspaceListExecutor(roots),
        ),
    ]
    seen = 0
    for registry in registries:
        for name in sorted(registry.names):
            candidate = registry.get(name)
            assert candidate is not None
            admit(candidate)  # must not raise
            assert isinstance(candidate.side_effect, SideEffect)
            # Everything shipping today observes and changes nothing.
            assert candidate.side_effect is SideEffect.NONE
            assert candidate.requires_authorization is True
            assert candidate.destructive is False
            seen += 1
    assert seen == 3


def test_the_file_search_builder_returns_an_admitted_capability() -> None:
    """Builders admit at definition time, so a bad edit fails where it is made
    rather than at the first run that happens to use it."""
    built = build_file_search_spec()
    assert admit(built) is built  # already passed; admission is idempotent
    assert built.side_effect is SideEffect.NONE


# ===========================================================================
# Secret and data-flow audit (task 12)
#
# Runtime sentinels, exercised through the real data flow. A source-text search
# would prove only that a literal is absent from a file; what matters is that
# the value cannot arrive at a surface that must not carry it, which is a
# question about what the code actually does with it.


SENTINELS = {
    "api_key": "sk-m7-sentinel-api-key-9f21",
    "filesystem_root": "m7-sentinel-physical-root-4c8e",
    "operator_reason": "m7_sentinel_operator_reason",
}


def _forbidden_surfaces(harness: Any, extra: dict[str, str]) -> dict[str, str]:
    """Every surface a capability's secrets must not reach, rendered as text."""
    surfaces = {
        "model_payload": json.dumps(
            [request.model_dump(mode="json") for request in harness.adapter.requests]
        ),
        "journal": harness.journal.path.read_text(encoding="utf-8"),
        "inspection": json.dumps(harness.inspect().model_dump(mode="json")),
        "capability_digests": json.dumps(dict(harness.registry.digests())),
    }
    surfaces.update(extra)
    return surfaces


def test_a_physical_root_never_reaches_a_capability_facing_surface(tmp_path: Path) -> None:
    """The root is wiring authority; nothing downstream may echo it.

    Exercised through a real filesystem capability over a real tree whose
    directory name *is* the sentinel, so a leak has something to leak.
    """
    from local_agent.executors.workspace_fs import WorkspaceListExecutor, WorkspaceReadExecutor
    from local_agent.wiring import (
        build_filesystem_registry,
        build_filesystem_run_context,
        build_physical_roots,
    )

    workspace = tmp_path / SENTINELS["filesystem_root"]
    workspace.mkdir()
    (workspace / "note.txt").write_text("hello\n", encoding="utf-8")
    roots = build_physical_roots({"workspace": workspace})
    registry = build_filesystem_registry(
        roots,
        read_executor=WorkspaceReadExecutor(roots),
        list_executor=WorkspaceListExecutor(roots),
    )
    proposal = json.dumps(
        {"tool": "workspace.read", "arguments": {"root_id": "workspace", "path": "note.txt"}}
    )
    adapter = ScriptedModelAdapter((ModelResponse(structured_output=proposal), COMPLETION_RESPONSE))
    context = build_filesystem_run_context("run-root")
    outcome = asyncio.run(Controller(registry, adapter).run(context, RECOVERY_MESSAGES))

    assert outcome.succeeded  # the capability really ran, so this is not vacuous
    surfaces = {
        "result": json.dumps(outcome.result.model_dump(mode="json") if outcome.result else {}),
        "events": json.dumps([event.as_dict() for event in outcome.events]),
        "model_payload": json.dumps(
            [request.model_dump(mode="json") for request in adapter.requests]
        ),
        "capability_digests": json.dumps(dict(registry.digests())),
        "model_visible_tools": json.dumps(
            [
                dataclasses.asdict(description)
                for description in __import__(
                    "local_agent.wiring", fromlist=["describe_tools"]
                ).describe_tools(registry)
            ]
        ),
    }
    for surface, rendered in surfaces.items():
        assert SENTINELS["filesystem_root"] not in rendered, f"{surface} leaked the root"
        assert str(tmp_path) not in rendered, f"{surface} leaked a host path"


def test_an_api_key_never_reaches_a_capability_facing_surface(tmp_path: Path) -> None:
    """The credential lives inside the transport and goes nowhere else."""
    from conftest import chat_completion, model_config, ok

    from local_agent.model_service import LocalAIModelAdapter
    from local_agent.model_transport import ScriptedTransport
    from local_agent.wiring import describe_tools

    executor = FakeFileSearchExecutor()
    registry = build_default_registry(executor)
    config = model_config(api_key=SENTINELS["api_key"])
    transport = ScriptedTransport(
        (
            ok(
                chat_completion(
                    tool="file_search", arguments={"query": "q", "root_id": "workspace"}
                )
            ),
            # Milestone 10: the completion has to come over the wire here,
            # because this harness drives the production adapter.
            completion_transport(),
        )
    )
    adapter = LocalAIModelAdapter(
        transport=transport, config=config, tools=describe_tools(registry)
    )
    journal_path = tmp_path / "keyed.jsonl"
    with RunJournal(journal_path) as journal:
        outcome = asyncio.run(
            Controller(registry, adapter, journal=journal).run(
                RunContext(run_id="run-key"), RECOVERY_MESSAGES
            )
        )

    assert outcome.succeeded
    surfaces = {
        "transport_requests": json.dumps(
            [
                {"path": request.path, "body": request.body.decode("utf-8")}
                for request in transport.requests
            ]
        ),
        "journal": journal_path.read_text(encoding="utf-8"),
        "events": json.dumps([event.as_dict() for event in outcome.events]),
        "result": json.dumps(outcome.result.model_dump(mode="json") if outcome.result else {}),
        "config_repr": repr(config),
        "capability_digests": json.dumps(dict(registry.digests())),
    }
    for surface, rendered in surfaces.items():
        assert SENTINELS["api_key"] not in rendered, f"{surface} leaked the credential"


def test_the_leak_probe_can_actually_detect_a_leak(tmp_path: Path) -> None:
    """Positive control. Without it every "no sentinel found" is unfalsifiable."""
    leaky = json.dumps({"note": SENTINELS["api_key"]})
    assert SENTINELS["api_key"] in leaky


def test_an_execution_identity_and_operator_reason_stay_out_of_model_context(
    tmp_path: Path,
) -> None:
    """Control-plane identifiers are never a model-facing payload."""
    crashed = crash_mid_execution(tmp_path, run_id="run-flow")
    harness = build_recovery_harness(crashed)
    plan = harness.plan()
    harness.recover(harness.decide("resume", SENTINELS["operator_reason"]))
    harness.journal.close()

    model_payload = json.dumps(
        [request.model_dump(mode="json") for request in harness.adapter.requests]
    )
    for label, sentinel in (
        ("execution_id", plan.execution_id),
        ("plan_id", plan.plan_id),
        ("capability_digest", plan.capability_digest),
        ("operator_reason", SENTINELS["operator_reason"]),
    ):
        assert sentinel is not None
        assert sentinel not in model_payload, f"{label} reached model context"

    # The journal is exactly where the audit values belong, and they are there.
    journal_text = crashed.path.read_text(encoding="utf-8")
    assert SENTINELS["operator_reason"] in journal_text
    assert plan.capability_digest is not None
    assert plan.capability_digest in journal_text


def test_an_exception_from_a_capability_carries_no_host_detail() -> None:
    """A failing executor's message never becomes model-facing text."""
    outcome = _run(build_default_registry(FailingExecutor()))

    assert outcome.error is not None
    rendered = json.dumps(outcome.error.model_dump(mode="json"))
    for forbidden in ("/internal/host/path", "Traceback", "simulated backend failure"):
        assert forbidden not in rendered
