"""The first non-re-executable mutation, under attack (Milestone 9).

Milestone 8 proved a side effect could be *governed*. This file asks the
harder question: can the architecture hold four facts apart when they finally
stop correlating?

    side_effect_free    could anything have happened?
    re_executable       if it may have happened, is repeating safe?
    journal evidence    what does the system actually know?
    disposition         what conclusion is justified?

Every capability before this one made at least two of those the same answer.
`workspace.append` is the first to sit in the fourth corner — not side-effect
free and not re-executable — so it is the first that can tell a real separation
from an accidental alignment.

Two counters matter here and they are not the same. `call_count` says the
executor was dispatched; `append_count` says bytes reached a disk. For an
`IDEMPOTENT` capability a repeated dispatch that landed is merely wasteful. For
this one it is the hazard the whole classification exists to prevent, so every
retry and recovery test asserts the *physical* count.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    AppendThenFailExecutor,
    CrashAfterAppendExecutor,
    SimulatedCrash,
    WriteFixture,
    WriteThenFailExecutor,
    append_proposal,
    build_append_harness,
    build_write_harness,
    build_write_tree,
    write_proposal,
)
from pydantic import ValidationError

from local_agent.contracts import (
    MAX_APPEND_CONTENT_CHARS,
    ModelResponse,
    WorkspaceAppendArgs,
    WorkspaceAppendResult,
)
from local_agent.executors.workspace_append import (
    WorkspaceAppendExecutor,
    build_workspace_append_spec,
)
from local_agent.executors.workspace_write import WorkspaceWriteExecutor
from local_agent.operator import OperatorDecision
from local_agent.persistence.journal import RunJournal
from local_agent.persistence.records import MAX_ARGUMENTS_BYTES
from local_agent.policy import DEFAULT_FILESYSTEM_LIMITS, FilesystemLimits, RunContext
from local_agent.recovery import RecoveryError, plan_recovery
from local_agent.registry import SideEffect, ToolRegistry, capability_digest
from local_agent.wiring import build_mutating_filesystem_registry, build_mutating_run_context

APPEND_LIMIT = DEFAULT_FILESYSTEM_LIMITS.max_file_append_bytes

# The seed every fixture file starts with, so "what changed" is unambiguous.
SEED = "original\n"


def _silent_adapter() -> Any:
    """An adapter that is wired in but must never be consulted.

    `ScriptedModelAdapter` refuses an empty script, so the operator tests give
    it one response they then assert was never requested. `adapter.call_count
    == 0` is the actual assertion; this exists so the zero is meaningful rather
    than an artifact of there being nothing to return.
    """
    from local_agent.model_adapter import ScriptedModelAdapter

    return ScriptedModelAdapter(
        (ModelResponse(structured_output=append_proposal("existing.txt", "never\n")),)
    )


def run_append(
    fixture: WriteFixture, path: str, content: str, root_id: str = "workspace", **kwargs: Any
) -> Any:
    """Drive one governed append and hand back the harness for its counters."""
    harness = build_append_harness(
        fixture, ModelResponse(structured_output=append_proposal(path, content, root_id)), **kwargs
    )
    return harness.run(), harness


# ===========================================================================
# The capability contract (§4 of the milestone report)
# ===========================================================================


def test_the_appender_occupies_the_fourth_corner_of_the_contract() -> None:
    """The whole milestone in one assertion.

    Before this capability existed, every `ToolSpec` in the project had
    `side_effect_free == (not re_executable) is False` — that is, the two
    derived properties never disagreed in the direction that matters. `NONE`
    gave (True, True) and `IDEMPOTENT` gave (False, True). Nothing gave
    (False, False), so nothing had ever exercised the branch where "something
    may have happened" and "repeating is unsafe" are both true at once.
    """
    spec = build_workspace_append_spec(WorkspaceAppendExecutor.__new__(WorkspaceAppendExecutor))

    assert spec.side_effect is SideEffect.MUTATING
    # Something observable happened, so an ambiguous crash is not "nothing".
    assert spec.side_effect_free is False
    # And repeating compounds it, so the controller may not run it again.
    assert spec.re_executable is False
    assert spec.requires_authorization is True
    # Appending removes nothing and overwrites nothing. `MUTATING` and
    # `destructive` are different axes; conflating them here would be the same
    # mistake this milestone exists to test against.
    assert spec.destructive is False


def test_the_two_side_effecting_capabilities_differ_only_in_classification() -> None:
    """A positive control for the corner above.

    If the appender and the writer differed in several respects, a test showing
    they behave differently would prove nothing about the classification. They
    differ in exactly one declared property.
    """
    from local_agent.executors.workspace_write import build_workspace_write_spec

    appender = build_workspace_append_spec(WorkspaceAppendExecutor.__new__(WorkspaceAppendExecutor))
    writer = build_workspace_write_spec(WorkspaceWriteExecutor.__new__(WorkspaceWriteExecutor))

    assert appender.requires_authorization == writer.requires_authorization
    assert appender.destructive == writer.destructive
    assert appender.timeout_seconds == writer.timeout_seconds
    assert appender.side_effect is not writer.side_effect
    assert appender.re_executable is not writer.re_executable


# ===========================================================================
# The formal criterion: R(R(S)) != R(S), inside the declared effect
# ===========================================================================


def test_applying_the_identical_request_twice_leaves_different_state(
    write_tree: WriteFixture,
) -> None:
    """The measurement that justifies `MUTATING`, against Milestone 8's own bound.

    Milestone 8 claimed idempotency *with respect to the destination artifact's
    existence and content*. That is a testable definition, and this capability
    fails it — not on metadata, not on an observer, but on the file's content,
    which is squarely inside the declared effect.
    """
    once, _ = run_append(write_tree, "existing.txt", "entry\n", run_id="run-once")
    after_one = (write_tree.workspace / "existing.txt").read_text(encoding="utf-8")

    twice, _ = run_append(write_tree, "existing.txt", "entry\n", run_id="run-twice")
    after_two = (write_tree.workspace / "existing.txt").read_text(encoding="utf-8")

    assert once.succeeded and twice.succeeded
    assert after_one == SEED + "entry\n"
    assert after_two == SEED + "entry\nentry\n"
    # The criterion itself, stated rather than implied by the strings above.
    assert after_two != after_one


def test_the_writer_under_the_same_pair_of_requests_converges(
    write_tree: WriteFixture,
) -> None:
    """The contrasting control, so the criterion is falsifiable.

    Without this, "appending twice differs from appending once" would be a fact
    about repetition in general rather than about this capability. The same two
    identical requests through `workspace.write` converge.
    """
    from conftest import build_write_harness as _harness

    for run_id in ("run-w1", "run-w2"):
        outcome = _harness(
            write_tree,
            ModelResponse(structured_output=write_proposal("existing.txt", "entry\n")),
            run_id=run_id,
        ).run()
        assert outcome.succeeded

    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == "entry\n"


# ===========================================================================
# Positive controls — the capability actually works
# ===========================================================================


def test_an_authorized_append_adds_exactly_the_requested_bytes(
    write_tree: WriteFixture,
) -> None:
    outcome, harness = run_append(write_tree, "existing.txt", "entry\n")

    assert outcome.succeeded
    assert harness.appends == 1
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED + "entry\n"
    assert outcome.result is not None
    assert outcome.result.model_dump(mode="json") == {
        "status": "success",
        "root_id": "workspace",
        "path": "existing.txt",
        "bytes_appended": 6,
    }


def test_an_append_into_a_nested_directory_is_permitted(write_tree: WriteFixture) -> None:
    outcome, harness = run_append(write_tree, "nested/deep.txt", "more\n")

    assert outcome.succeeded
    assert harness.appends == 1
    assert (write_tree.workspace / "nested" / "deep.txt").read_text(
        encoding="utf-8"
    ) == "deep\nmore\n"


def test_an_empty_append_is_a_real_execution_that_changes_nothing(
    write_tree: WriteFixture,
) -> None:
    """The empty payload is legal and is deliberately not special-cased.

    Refusing it, or short-circuiting before the open, would put a
    capability-specific branch into an otherwise uniform pipeline — and it
    would make `bytes_appended == 0` unreachable, hiding the one result value
    that distinguishes "nothing to add" from "nothing happened".
    """
    outcome, harness = run_append(write_tree, "existing.txt", "")

    assert outcome.succeeded
    assert harness.appends == 1  # it really executed
    assert outcome.result is not None
    assert outcome.result.bytes_appended == 0
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED


def test_the_result_reports_encoded_bytes_not_characters(write_tree: WriteFixture) -> None:
    outcome, _ = run_append(write_tree, "existing.txt", "\u4e2d\u6587")  # 2 chars, 6 bytes

    assert outcome.succeeded
    assert outcome.result is not None
    assert outcome.result.bytes_appended == 6


# ===========================================================================
# Contract adversarial matrix (§16 — contract)
# ===========================================================================


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("missing_path", {"root_id": "workspace", "content": "x"}),
        ("missing_root", {"path": "a.txt", "content": "x"}),
        ("missing_content", {"root_id": "workspace", "path": "a.txt"}),
        ("extra_field", {"root_id": "workspace", "path": "a.txt", "content": "x", "mode": "a"}),
        ("extra_offset", {"root_id": "workspace", "path": "a.txt", "content": "x", "offset": 0}),
        ("wrong_content_type", {"root_id": "workspace", "path": "a.txt", "content": 5}),
        ("wrong_path_type", {"root_id": "workspace", "path": 5, "content": "x"}),
        ("unknown_root", {"root_id": "elsewhere", "path": "a.txt", "content": "x"}),
        ("empty_path", {"root_id": "workspace", "path": "", "content": "x"}),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_the_argument_schema_refuses_malformed_requests(
    label: str, payload: dict[str, Any]
) -> None:
    """`extra="forbid"` is what makes `offset` and `mode` schema violations.

    An append with a caller-chosen offset would be a different capability
    wearing this one's name, and the enforcement is that the type has no
    vocabulary for it rather than a check somewhere that rejects it.
    """
    with pytest.raises(ValidationError):
        WorkspaceAppendArgs(**payload)


# The same hostile paths Milestone 2 refuses, re-run against this capability.
# They are refused by the shared `RelativePath` grammar at VALIDATE, before
# authorization and before any filesystem call — but "the same validator is
# reused" is a claim worth re-proving per capability, because a future edit
# could give this one its own grammar.
HOSTILE_PATHS = [
    ("absolute", "/etc/passwd"),
    ("parent_escape", "../external/secret.txt"),
    ("nested_escape", "nested/../../external/secret.txt"),
    ("dot_segment", "./existing.txt"),
    ("backslash", "..\\external\\secret.txt"),
    ("drive", "C:/windows/system32"),
    ("unc", "//server/share"),
    ("nul", "existing\x00.txt"),
    ("home", "~/secret"),
    ("double_separator", "nested//deep.txt"),
    ("trailing_separator", "nested/"),
    ("bare_parent", ".."),
]


@pytest.mark.parametrize(("label", "path"), HOSTILE_PATHS, ids=lambda v: v)
def test_hostile_paths_are_refused_by_the_contract(label: str, path: str) -> None:
    with pytest.raises(ValidationError):
        WorkspaceAppendArgs(root_id="workspace", path=path, content="x")


@pytest.mark.parametrize(("label", "path"), HOSTILE_PATHS, ids=lambda v: v)
def test_hostile_paths_perform_no_physical_append(
    write_tree: WriteFixture, label: str, path: str
) -> None:
    """The three-part assertion: refused, nothing appended, sentinel intact."""
    outcome, harness = run_append(write_tree, path, "OWNED\n")

    assert not outcome.succeeded
    assert harness.appends == 0
    assert write_tree.outside_intact()


# ===========================================================================
# Containment and file-type policy (§16 — execution)
# ===========================================================================


@pytest.mark.parametrize(
    ("label", "path"),
    [
        ("symlink_outside", "link_outside.txt"),
        ("symlink_inside", "link_inside.txt"),
        ("symlink_broken", "link_broken.txt"),
        ("symlink_other_root", "link_other_root"),
        ("symlinked_parent", "link_dir_outside/secret.txt"),
        ("directory", "a_directory"),
        ("fifo", "a_fifo"),
    ],
    ids=lambda v: v,
)
def test_non_regular_and_symlinked_destinations_are_refused(
    write_tree: WriteFixture, label: str, path: str
) -> None:
    outcome, harness = run_append(write_tree, path, "OWNED\n")

    assert not outcome.succeeded
    assert harness.appends == 0
    assert write_tree.outside_intact()


def test_a_missing_destination_is_refused_and_never_created(write_tree: WriteFixture) -> None:
    """ "Never creates a file" is a property of the flags, not of a guard.

    There is no `O_CREAT` in `_APPEND_FLAGS`, so even if the explicit existence
    check were deleted the kernel would refuse with `ENOENT`. The check exists
    to produce a stable slug rather than a bare errno.
    """
    outcome, harness = run_append(write_tree, "absent.txt", "entry\n")

    assert not outcome.succeeded
    assert harness.appends == 0
    assert not (write_tree.workspace / "absent.txt").exists()


def test_a_missing_parent_directory_is_refused_and_never_created(
    write_tree: WriteFixture,
) -> None:
    outcome, harness = run_append(write_tree, "no_such_dir/file.txt", "entry\n")

    assert not outcome.succeeded
    assert harness.appends == 0
    assert not (write_tree.workspace / "no_such_dir").exists()


def test_a_non_regular_destination_is_refused_before_any_open(
    write_tree: WriteFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ordering, not outcome — the Milestone 8 liveness finding, re-proved here.

    `os.open` on a FIFO without `O_NONBLOCK` blocks until a reader appears and
    no timeout is enforced anywhere, so a removed type check hangs the
    controller rather than degrading its error. A hang is not a failure, so
    asserting the outcome cannot catch it; the assertion is that the dangerous
    call is never reached.
    """
    import os

    opened: list[str] = []
    real_open = os.open

    def recording_open(path: Any, flags: int, mode: int = 0o777, **kwargs: Any) -> int:
        opened.append(str(path))
        if str(path).endswith("a_fifo"):
            raise AssertionError("os.open was handed a FIFO destination")
        return real_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)
    outcome, harness = run_append(write_tree, "a_fifo", "x\n")

    assert not outcome.succeeded
    assert harness.appends == 0
    assert not any(candidate.endswith("a_fifo") for candidate in opened)


def test_the_append_open_spy_records_a_real_open(
    write_tree: WriteFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positive control for the spy above (testing rule 16)."""
    import os

    opened: list[str] = []
    real_open = os.open

    def recording_open(path: Any, flags: int, mode: int = 0o777, **kwargs: Any) -> int:
        opened.append(str(path))
        return real_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)
    outcome, _ = run_append(write_tree, "existing.txt", "x\n")

    assert outcome.succeeded
    assert any(candidate.endswith("existing.txt") for candidate in opened)


# ===========================================================================
# Size ceiling
# ===========================================================================


def test_content_exactly_at_the_append_ceiling_is_written(write_tree: WriteFixture) -> None:
    outcome, harness = run_append(write_tree, "existing.txt", "x" * APPEND_LIMIT)

    assert outcome.succeeded
    assert harness.appends == 1
    assert (write_tree.workspace / "existing.txt").stat().st_size == len(SEED) + APPEND_LIMIT


@pytest.mark.parametrize("size", [APPEND_LIMIT + 1, APPEND_LIMIT * 3], ids=["one_over", "far_over"])
def test_oversized_content_causes_no_physical_append(write_tree: WriteFixture, size: int) -> None:
    outcome, harness = run_append(write_tree, "existing.txt", "x" * size)

    assert not outcome.succeeded
    assert harness.appends == 0
    # The file is untouched, which for an append is a stronger statement than
    # "not created": a partial append would be invisible to an existence check.
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED


def test_the_append_ceiling_is_on_encoded_bytes_not_characters(
    write_tree: WriteFixture,
) -> None:
    payload = "\u4e2d" * (APPEND_LIMIT // 2)  # under the char cap, over the byte cap
    assert len(payload) < MAX_APPEND_CONTENT_CHARS
    assert len(payload.encode("utf-8")) > APPEND_LIMIT

    outcome, harness = run_append(write_tree, "existing.txt", payload)

    assert not outcome.succeeded
    assert harness.appends == 0
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED


def test_the_append_ceiling_is_its_own_field_and_tighter_than_the_write_ceiling() -> None:
    """The one place this capability's semantics show up in policy.

    A write replaces, so its ceiling bounds the artifact. An append
    accumulates, so the per-call ceiling bounds nothing about the artifact —
    N authorized appends grow a file by N times this value. Tightening it does
    not make growth bounded; it records that the two were reasoned about
    separately, and stops one being raised for the other's reasons.
    """
    assert DEFAULT_FILESYSTEM_LIMITS.max_file_append_bytes < (
        DEFAULT_FILESYSTEM_LIMITS.max_file_write_bytes
    )
    # Arguments are persisted before execution, so the same journal coupling
    # the write ceiling has applies here.
    assert DEFAULT_FILESYSTEM_LIMITS.max_file_append_bytes < MAX_ARGUMENTS_BYTES

    tightened = FilesystemLimits(max_file_append_bytes=16)
    assert tightened.max_file_append_bytes == 16
    assert tightened.max_file_write_bytes == DEFAULT_FILESYSTEM_LIMITS.max_file_write_bytes
    with pytest.raises(ValueError):
        FilesystemLimits(max_file_append_bytes=0)


def test_a_tightened_append_limit_is_honoured(write_tree: WriteFixture) -> None:
    outcome, harness = run_append(
        write_tree, "existing.txt", "x" * 17, limits=FilesystemLimits(max_file_append_bytes=16)
    )

    assert not outcome.succeeded
    assert harness.appends == 0
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED


# ===========================================================================
# Authorization (§16 — authorization)
# ===========================================================================


def test_an_unauthorized_run_cannot_append(write_tree: WriteFixture) -> None:
    outcome, harness = run_append(
        write_tree,
        "existing.txt",
        "entry\n",
        run_context=RunContext(run_id="run-none", authorized_tools=frozenset()),
    )

    assert not outcome.succeeded
    assert harness.appends == 0
    assert harness.executor.call_count == 0
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED


def test_a_write_grant_does_not_imply_an_append_grant(write_tree: WriteFixture) -> None:
    """The grants are per capability, and this is the pair that matters most.

    "May replace a file" and "may append to a file" are close enough that a
    deployment might assume one implies the other. It does not, and the
    escalation from `IDEMPOTENT` to `MUTATING` is exactly where an implicit
    widening would do the most damage.
    """
    from local_agent.wiring import build_writable_run_context

    outcome, harness = run_append(
        write_tree, "existing.txt", "entry\n", run_context=build_writable_run_context("run-w")
    )

    assert not outcome.succeeded
    assert harness.appends == 0
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED


def test_an_unauthorized_root_cannot_be_appended_to(write_tree: WriteFixture) -> None:
    (write_tree.knowledge / "notes.txt").write_text("notes\n", encoding="utf-8")
    outcome, harness = run_append(
        write_tree,
        "notes.txt",
        "entry\n",
        root_id="knowledge",
        run_context=build_mutating_run_context(
            "run-narrow", authorized_roots=frozenset({"workspace"})
        ),
    )

    assert not outcome.succeeded
    assert harness.appends == 0
    assert (write_tree.knowledge / "notes.txt").read_text(encoding="utf-8") == "notes\n"


def test_the_read_only_and_writable_registries_contain_no_appender(
    write_tree: WriteFixture,
) -> None:
    """Escalation is monotonic and has to be asked for by name.

    Three builders, three capability sets. Nothing a caller of the first two
    does can produce the third — there is no `include_mutation=True`.
    """
    from local_agent.wiring import build_filesystem_registry, build_writable_filesystem_registry

    read_only = build_filesystem_registry(write_tree.roots)
    writable = build_writable_filesystem_registry(write_tree.roots)
    mutating = build_mutating_filesystem_registry(write_tree.roots)

    assert read_only.names == frozenset({"workspace.read", "workspace.list"})
    assert "workspace.append" not in writable.names
    assert writable.get("workspace.append") is None
    assert "workspace.append" in mutating.names


def test_the_read_only_and_writable_run_contexts_grant_no_append() -> None:
    from local_agent.wiring import build_filesystem_run_context, build_writable_run_context

    assert "workspace.append" not in build_filesystem_run_context("r").authorized_tools
    assert "workspace.append" not in build_writable_run_context("r").authorized_tools
    assert "workspace.append" in build_mutating_run_context("r").authorized_tools


# ===========================================================================
# §11 THE RETRY PROOF — physical execution counts, not in-memory booleans
# ===========================================================================


def test_a_mutating_capability_is_never_automatically_retried(
    write_tree: WriteFixture,
) -> None:
    """The central Milestone 9 proof.

    The executor performs a *real* append and then raises a retryable error, so
    every precondition for a retry is satisfied except the capability's own
    classification: the error is in `RETRYABLE_CODES`, the budget is three, and
    the model has further responses queued.

    One physical append. Not three. And the file proves it — counting the spy
    alone would pass even if the bytes had gone somewhere else.
    """
    spy = AppendThenFailExecutor(WorkspaceAppendExecutor(write_tree.roots))
    harness = build_append_harness(
        write_tree,
        [ModelResponse(structured_output=append_proposal("existing.txt", "x\n"))] * 5,
        executor=spy,
    )

    outcome = harness.run()

    assert not outcome.succeeded
    assert outcome.error is not None
    # The error really was retryable; the capability is what withheld the retry.
    assert outcome.error.retryable is True
    assert spy.append_count == 1
    assert spy.call_count == 1
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED + "x\n"


def test_the_idempotent_writer_is_still_retried_three_times(
    write_tree: WriteFixture,
) -> None:
    """The positive control §11 requires, and the reason the test above means anything.

    Identical harness shape, identical error, identical budget — only the
    classification differs. Three physical writes. If this dropped to one, the
    test above would be passing because retry was broken generally rather than
    because `re_executable` was consulted.
    """
    spy = WriteThenFailExecutor(WorkspaceWriteExecutor(write_tree.roots))
    harness = build_write_harness(
        write_tree,
        [ModelResponse(structured_output=write_proposal("existing.txt", "x\n"))] * 5,
        executor=spy,
    )

    outcome = harness.run()

    assert not outcome.succeeded
    assert spy.write_count == 3
    assert spy.call_count == 3


def test_a_mutating_capability_with_a_non_retryable_error_also_runs_once(
    write_tree: WriteFixture,
) -> None:
    """The other half of the §11 matrix.

    A non-retryable error stops after one execution for reasons that have
    nothing to do with the capability gate, so this case cannot distinguish the
    two mechanisms — which is exactly why it is asserted separately rather than
    being treated as evidence for the gate.
    """
    outcome, harness = run_append(write_tree, "a_directory", "x\n")

    assert not outcome.succeeded
    assert harness.appends == 0


def test_a_rejection_before_the_executor_leaves_the_repair_loop_intact(
    write_tree: WriteFixture,
) -> None:
    """`invoked is None` means nothing ran, so the ordinary retry rules apply.

    The capability gate must not turn a `MUTATING` capability into "one
    malformed proposal and the run is over". A schema-level rejection never
    reached the executor, so the model still gets its repair attempts — and the
    physical count stays zero throughout.
    """
    harness = build_append_harness(
        write_tree,
        [
            ModelResponse(structured_output=json.dumps({"tool": "workspace.append"})),
            ModelResponse(structured_output=json.dumps({"tool": "workspace.append"})),
            ModelResponse(structured_output=append_proposal("existing.txt", "recovered\n")),
        ],
    )

    outcome = harness.run()

    assert outcome.succeeded
    assert harness.appends == 1
    assert harness.executor.call_count == 1
    assert (write_tree.workspace / "existing.txt").read_text(
        encoding="utf-8"
    ) == SEED + "recovered\n"


def test_the_withheld_retry_is_reported_to_the_audit_stream_not_the_model(
    write_tree: WriteFixture,
) -> None:
    """The classification must not leak onto a model-facing channel."""
    spy = AppendThenFailExecutor(WorkspaceAppendExecutor(write_tree.roots))
    harness = build_append_harness(
        write_tree,
        [ModelResponse(structured_output=append_proposal("existing.txt", "x\n"))] * 3,
        executor=spy,
    )

    outcome = harness.run()

    withheld = [event for event in outcome.events if event.type == "retry_withheld"]
    assert len(withheld) == 1
    assert dict(withheld[0].detail)["reason"] == "capability_not_re_executable"
    # What the model was told carries no classification vocabulary.
    rendered = json.dumps([request.model_dump(mode="json") for request in harness.adapter.requests])
    for forbidden in ("re_executable", "MUTATING", "side_effect", "capability_not_re_executable"):
        assert forbidden not in rendered


# ===========================================================================
# §12 RECOVERY — cases A through H
# ===========================================================================


def _journalled(
    write_tree: WriteFixture,
    tmp_path: Path,
    run_id: str,
    *,
    executor: Any = None,
    journal_factory: Any = None,
    path: str = "existing.txt",
    content: str = "entry\n",
) -> tuple[Path, Any]:
    """Drive one append to a crash and hand back the journal path."""
    journal_path = tmp_path / f"{run_id}.jsonl"
    journal = (journal_factory or RunJournal)(journal_path)
    harness = build_append_harness(
        write_tree,
        ModelResponse(structured_output=append_proposal(path, content)),
        executor=executor,
        journal=journal,
        run_context=build_mutating_run_context(run_id),
    )
    try:
        harness.run()
    except SimulatedCrash:
        pass
    finally:
        journal.close()
    return journal_path, harness


def _plan(write_tree: WriteFixture, journal_path: Path, run_id: str) -> Any:
    registry = build_mutating_filesystem_registry(write_tree.roots)
    with RunJournal(journal_path) as journal:
        return plan_recovery(journal.records(), registry, build_mutating_run_context(run_id))


def test_case_a_crash_before_the_authorization_is_durable_appends_nothing(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """Case A: the effect definitely did not happen.

    The write-ahead record never landed, so the executor was never reached.
    This is the one disposition where "did not execute" is a *fact* rather than
    an inference, and the file is the evidence.
    """
    from conftest import CrashingJournal

    journal_path, harness = _journalled(
        write_tree,
        tmp_path,
        "run-a",
        journal_factory=lambda p: CrashingJournal(p, crash_before="execution_authorized"),
    )

    assert harness.appends == 0
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED

    plan = _plan(write_tree, journal_path, "run-a")
    assert plan.disposition == "no_execution_authorized"
    assert "resume" not in plan.available_actions


def test_case_b_crash_after_the_append_is_unknown_and_offers_no_resume(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """Case B: the milestone's whole point, measured end to end.

    Bytes are physically in the file. No completion evidence exists. The
    architecture must say "may have happened" without claiming either that it
    did or that it did not, and must refuse to repeat it automatically.
    """
    crasher = CrashAfterAppendExecutor(WorkspaceAppendExecutor(write_tree.roots))
    journal_path, _ = _journalled(write_tree, tmp_path, "run-b", executor=crasher, content="boom\n")

    # The effect really happened.
    assert crasher.append_count == 1
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED + "boom\n"

    plan = _plan(write_tree, journal_path, "run-b")

    # Evidence axis: unknown, because nothing recorded the outcome.
    assert plan.disposition == "execution_unknown"
    assert plan.reason_code == "execution_outcome_unknown"
    assert plan.side_effect_free is False
    # Safety axis: repeating is unsafe, so no resume is offered.
    assert plan.re_executable is False
    assert "resume" not in plan.available_actions
    assert plan.requires_operator is True
    # And it is emphatically not reported as either resolved state.
    assert plan.execution_status is None


def test_case_c_a_completed_append_is_recognised_as_completed(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """Case C: completion evidence exists, and no stronger claim is made.

    `execution_completed` says the physical call finished. It does not say the
    run succeeded, and it still offers no resume — the journal deliberately
    never retains a result, so the only way to produce one would be to execute
    a second time.
    """
    from conftest import CrashingJournal

    journal_path, harness = _journalled(
        write_tree,
        tmp_path,
        "run-c",
        journal_factory=lambda p: CrashingJournal(p, crash_after="execution_completed"),
    )

    assert harness.appends == 1
    plan = _plan(write_tree, journal_path, "run-c")

    assert plan.disposition == "execution_completed"
    assert plan.execution_status == "succeeded"
    # Completion is not resumability: the journal never retained the result, so
    # producing one would mean executing a second time.
    assert "resume" not in plan.available_actions


def test_case_d_a_clean_failure_records_completion_and_is_not_unknown(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """Case D, and the distinction it turns on.

    A failure is not an absence of evidence. When the executor raises cleanly
    the controller records `ExecutionCompleted(status="failed")`, which closes
    the ambiguity window: the physical call is *known* to have finished, badly.
    Only a crash leaves the window open. Collapsing these two would be exactly
    the "unknown means failed" error §14 forbids.
    """
    from conftest import CrashingJournal

    spy = AppendThenFailExecutor(WorkspaceAppendExecutor(write_tree.roots))
    journal_path, _ = _journalled(
        write_tree,
        tmp_path,
        "run-d",
        executor=spy,
        journal_factory=lambda p: CrashingJournal(p, crash_after="execution_completed"),
    )

    assert spy.append_count == 1
    plan = _plan(write_tree, journal_path, "run-d")

    assert plan.disposition == "execution_completed"
    assert plan.execution_status == "failed"
    # Failed, and therefore *not* unknown. Different states, different words.
    assert plan.disposition != "execution_unknown"


def test_case_e_a_changed_capability_definition_blocks_recovery(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """Case E: recovery will not assume the current code matches the record."""
    from conftest import CrashingJournal

    journal_path, _ = _journalled(
        write_tree,
        tmp_path,
        "run-e",
        journal_factory=lambda p: CrashingJournal(p, crash_after="execution_authorized"),
    )

    altered = ToolRegistry(
        (
            dataclasses.replace(
                build_workspace_append_spec(WorkspaceAppendExecutor(write_tree.roots)),
                timeout_seconds=9.0,
            ),
        )
    )
    with RunJournal(journal_path) as journal, pytest.raises(RecoveryError) as caught:
        plan_recovery(journal.records(), altered, build_mutating_run_context("run-e"))
    assert caught.value.reason == "journal_capability_digest_mismatch"


def test_case_e_reclassifying_the_capability_is_detected_by_the_digest(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """The reclassification attack this milestone makes possible.

    Silently changing `MUTATING` to `IDEMPOTENT` after an authorization was
    recorded would make a non-repeatable execution look repeatable. Because
    `side_effect` feeds the capability digest, recovery refuses the journal
    instead of believing the new definition.
    """
    from conftest import CrashingJournal

    journal_path, _ = _journalled(
        write_tree,
        tmp_path,
        "run-e2",
        journal_factory=lambda p: CrashingJournal(p, crash_after="execution_authorized"),
    )

    honest = build_workspace_append_spec(WorkspaceAppendExecutor(write_tree.roots))
    downgraded = dataclasses.replace(honest, side_effect=SideEffect.IDEMPOTENT)
    # The digest actually changes — otherwise the refusal below would be
    # proving something else.
    assert capability_digest(honest) != capability_digest(downgraded)

    with RunJournal(journal_path) as journal, pytest.raises(RecoveryError) as caught:
        plan_recovery(
            journal.records(), ToolRegistry((downgraded,)), build_mutating_run_context("run-e2")
        )
    assert caught.value.reason in {
        "journal_capability_digest_mismatch",
        "journal_side_effect_mismatch",
    }


def test_case_f_a_tampered_execution_identity_is_refused(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """Case F: an identity that does not re-derive is not evidence of anything.

    The checksum is recomputed after the mutation, as testing rule 12 requires,
    so this proves re-derivation rather than merely proving the checksum works.
    """
    from conftest import CrashingJournal

    journal_path, _ = _journalled(
        write_tree,
        tmp_path,
        "run-f",
        journal_factory=lambda p: CrashingJournal(p, crash_after="execution_authorized"),
    )

    from local_agent.persistence.records import canonical_json, checksum

    lines = journal_path.read_text(encoding="utf-8").splitlines()
    rewritten: list[str] = []
    for line in lines:
        payload = json.loads(line)
        record = payload["record"]
        if record.get("type") == "execution_authorized":
            record["execution_id"] = "f" * 32
            # Recomputed, per testing rule 12: an attacker who can edit the
            # record can recompute the checksum, so leaving a stale one would
            # prove only that the checksum works. The defence under test is
            # re-derivation of the identity from the record's own contents.
            payload["checksum"] = checksum(canonical_json(record))
        rewritten.append(json.dumps(payload))
    journal_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")

    with RunJournal(journal_path) as journal, pytest.raises(RecoveryError) as caught:
        plan_recovery(
            journal.records(),
            build_mutating_filesystem_registry(write_tree.roots),
            build_mutating_run_context("run-f"),
        )
    assert "execution_id" in caught.value.reason or "identity" in caught.value.reason


def test_case_g_a_narrowed_grant_blocks_recovery(write_tree: WriteFixture, tmp_path: Path) -> None:
    """Case G: authority is re-established from the live context, not the file."""
    from conftest import CrashingJournal

    journal_path, _ = _journalled(
        write_tree,
        tmp_path,
        "run-g",
        journal_factory=lambda p: CrashingJournal(p, crash_after="execution_authorized"),
    )

    registry = build_mutating_filesystem_registry(write_tree.roots)
    narrowed = RunContext(run_id="run-g", authorized_tools=frozenset())
    with RunJournal(journal_path) as journal:
        plan = plan_recovery(journal.records(), registry, narrowed)

    assert plan.authorization_valid is False
    assert "resume" not in plan.available_actions
    # Still not resolved into a lie in either direction.
    assert plan.disposition == "execution_unknown"


def test_case_h_a_disappeared_capability_fails_safely(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """Case H: recovery refuses rather than bypassing capability validation."""
    from conftest import CrashingJournal

    journal_path, _ = _journalled(
        write_tree,
        tmp_path,
        "run-h",
        journal_factory=lambda p: CrashingJournal(p, crash_after="execution_authorized"),
    )

    with RunJournal(journal_path) as journal, pytest.raises(RecoveryError):
        plan_recovery(journal.records(), ToolRegistry(()), build_mutating_run_context("run-h"))


def test_recovery_never_reaches_an_executor(write_tree: WriteFixture, tmp_path: Path) -> None:
    """Planning is a read. It cannot append, whatever the journal says."""
    crasher = CrashAfterAppendExecutor(WorkspaceAppendExecutor(write_tree.roots))
    journal_path, _ = _journalled(
        write_tree, tmp_path, "run-noexec", executor=crasher, content="once\n"
    )
    before = (write_tree.workspace / "existing.txt").read_text(encoding="utf-8")

    for _ in range(5):
        plan = _plan(write_tree, journal_path, "run-noexec")
        assert plan.disposition == "execution_unknown"

    assert crasher.append_count == 1
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == before


# ===========================================================================
# §13 OPERATOR — the terminal control-plane path
# ===========================================================================


def _terminal_decision(plan: Any, action: str, reason: str) -> OperatorDecision:
    """Bind a control-plane decision to exactly this plan and this execution.

    `expected_execution_id` is required even for an action that executes
    nothing, and the binding is checked in both directions — omitting one for a
    plan that has an execution is refused just as naming one for a plan that
    does not. So an operator cannot close *a* run; they close the run whose
    ambiguity they were shown.
    """
    return OperatorDecision(
        run_id=plan.run_id,
        plan_id=plan.plan_id,
        action=action,
        decision_sequence=plan.next_decision_sequence,
        reason_code=reason,
        expected_execution_id=plan.execution_id,
    )


@pytest.mark.parametrize(
    ("action", "reason", "status", "code"),
    [
        ("abort", "effect_unverifiable", "aborted", "OPERATOR_ABORT"),
        ("terminalize", "closing_unresolved", "failed", "OPERATOR_TERMINALIZED"),
    ],
    ids=["abort", "terminalize"],
)
def test_an_operator_can_terminate_a_run_whose_effect_is_unknown(
    write_tree: WriteFixture, tmp_path: Path, action: str, reason: str, status: str, code: str
) -> None:
    """M9 must not create an operational dead end, and it does not.

    Automatic resume is forbidden and automatic retry is forbidden, but the run
    still reaches a terminal state through a control-plane transition — with no
    executor invoked and no bytes added.
    """
    crasher = CrashAfterAppendExecutor(WorkspaceAppendExecutor(write_tree.roots))
    journal_path, _ = _journalled(
        write_tree, tmp_path, f"run-op-{action}", executor=crasher, content="stuck\n"
    )
    after_crash = (write_tree.workspace / "existing.txt").read_text(encoding="utf-8")

    plan = _plan(write_tree, journal_path, f"run-op-{action}")
    assert action in plan.available_actions

    fresh = WorkspaceAppendExecutor(write_tree.roots)
    registry = build_mutating_filesystem_registry(write_tree.roots, append_executor=fresh)
    from local_agent.controller import Controller

    adapter = _silent_adapter()
    with RunJournal(journal_path) as journal:
        controller = Controller(registry, adapter, journal=journal)
        outcome = asyncio.run(
            controller.recover(
                build_mutating_run_context(f"run-op-{action}"),
                _terminal_decision(plan, action, reason),
            )
        )

    assert outcome.action == action
    assert outcome.executed is False
    # No executor, no model, no further bytes.
    assert fresh.append_count == 0
    assert fresh.call_count == 0
    assert adapter.call_count == 0
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == after_crash

    # The run is terminal, and terminal runs offer nothing further.
    final = _plan(write_tree, journal_path, f"run-op-{action}")
    assert final.disposition == "terminal"
    assert final.terminal_status == status
    assert final.terminal_code == code
    assert final.available_actions == ()


def test_terminating_the_run_does_not_rewrite_the_execution_as_not_having_happened(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """§14, at the durable level: what ends is the *run*, not the uncertainty.

    An operator closing an unresolvable run is a statement about the run's
    lifecycle. It is not a claim that the append did not occur, and the journal
    must keep saying so — the authorization with no completion stays on disk
    exactly as written, beside the terminal record.
    """
    crasher = CrashAfterAppendExecutor(WorkspaceAppendExecutor(write_tree.roots))
    journal_path, _ = _journalled(
        write_tree, tmp_path, "run-keep", executor=crasher, content="kept\n"
    )
    plan = _plan(write_tree, journal_path, "run-keep")

    from local_agent.controller import Controller

    with RunJournal(journal_path) as journal:
        controller = Controller(
            build_mutating_filesystem_registry(write_tree.roots),
            _silent_adapter(),
            journal=journal,
        )
        asyncio.run(
            controller.recover(
                build_mutating_run_context("run-keep"),
                _terminal_decision(plan, "terminalize", "unresolvable"),
            )
        )

    with RunJournal(journal_path) as journal:
        records = [record for _, record in journal.records()]
    authorizations = [r for r in records if r.type == "execution_authorized"]
    completions = [r for r in records if r.type == "execution_completed"]
    terminals = [r for r in records if r.type == "run_terminal"]

    assert len(authorizations) == 1
    assert authorizations[0].side_effect_free is False
    # No completion was fabricated to tidy the run up.
    assert completions == []
    assert len(terminals) == 1
    # The bytes are still there, and nothing claims otherwise.
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == SEED + "kept\n"


def test_an_operator_cannot_resume_a_non_re_executable_execution(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """The escape hatch is not a bypass.

    `resume` is absent from `available_actions`, and submitting it anyway is
    refused rather than honoured. An operator is a trusted actor and an
    untrusted source of values; this is the half that matters here.
    """
    from local_agent.controller import Controller
    from local_agent.operator import OperatorDecisionRejected

    crasher = CrashAfterAppendExecutor(WorkspaceAppendExecutor(write_tree.roots))
    journal_path, _ = _journalled(
        write_tree, tmp_path, "run-noresume", executor=crasher, content="no\n"
    )
    before = (write_tree.workspace / "existing.txt").read_text(encoding="utf-8")
    plan = _plan(write_tree, journal_path, "run-noresume")
    assert "resume" not in plan.available_actions

    fresh = WorkspaceAppendExecutor(write_tree.roots)
    registry = build_mutating_filesystem_registry(write_tree.roots, append_executor=fresh)
    with RunJournal(journal_path) as journal:
        controller = Controller(registry, _silent_adapter(), journal=journal)
        with pytest.raises(OperatorDecisionRejected) as caught:
            asyncio.run(
                controller.recover(
                    build_mutating_run_context("run-noresume"),
                    OperatorDecision(
                        run_id=plan.run_id,
                        plan_id=plan.plan_id,
                        action="resume",
                        decision_sequence=plan.next_decision_sequence,
                        reason_code="i_am_sure",
                        expected_execution_id=plan.execution_id,
                    ),
                )
            )

    # Refused at the *binding* layer, which is stronger than being refused
    # later by the controller: the decision never becomes a decision at all,
    # so there is no recorded approval for a subsequent change to re-interpret.
    assert caught.value.reason == "decision_action_not_available"
    assert fresh.append_count == 0
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == before


def test_a_passive_operator_action_changes_no_bytes_and_no_disposition(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """`acknowledge` records that a human looked. It grants nothing."""
    from local_agent.controller import Controller

    crasher = CrashAfterAppendExecutor(WorkspaceAppendExecutor(write_tree.roots))
    journal_path, _ = _journalled(
        write_tree, tmp_path, "run-ack", executor=crasher, content="seen\n"
    )
    before = (write_tree.workspace / "existing.txt").read_text(encoding="utf-8")
    plan = _plan(write_tree, journal_path, "run-ack")

    fresh = WorkspaceAppendExecutor(write_tree.roots)
    registry = build_mutating_filesystem_registry(write_tree.roots, append_executor=fresh)
    with RunJournal(journal_path) as journal:
        controller = Controller(registry, _silent_adapter(), journal=journal)
        outcome = asyncio.run(
            controller.recover(
                build_mutating_run_context("run-ack"),
                _terminal_decision(plan, "acknowledge", "noted"),
            )
        )

    assert outcome.executed is False
    assert fresh.append_count == 0
    assert (write_tree.workspace / "existing.txt").read_text(encoding="utf-8") == before

    after = _plan(write_tree, journal_path, "run-ack")
    # Still unknown, still not resumable, still terminable.
    assert after.disposition == "execution_unknown"
    assert "resume" not in after.available_actions
    assert "terminalize" in after.available_actions


def test_repeated_operator_termination_is_deterministic(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """A second terminal decision is refused, not applied twice."""
    from local_agent.controller import Controller
    from local_agent.operator import OperatorDecisionRejected

    crasher = CrashAfterAppendExecutor(WorkspaceAppendExecutor(write_tree.roots))
    journal_path, _ = _journalled(
        write_tree, tmp_path, "run-twice-op", executor=crasher, content="x\n"
    )
    plan = _plan(write_tree, journal_path, "run-twice-op")
    decision = _terminal_decision(plan, "abort", "done")

    fresh = WorkspaceAppendExecutor(write_tree.roots)
    registry = build_mutating_filesystem_registry(write_tree.roots, append_executor=fresh)
    with RunJournal(journal_path) as journal:
        controller = Controller(registry, _silent_adapter(), journal=journal)
        asyncio.run(controller.recover(build_mutating_run_context("run-twice-op"), decision))
        with pytest.raises(OperatorDecisionRejected) as caught:
            asyncio.run(controller.recover(build_mutating_run_context("run-twice-op"), decision))

    # A terminal run offers no actions, so replaying the same decision is
    # refused for that reason rather than being applied a second time.
    assert caught.value.reason == "run_is_terminal"
    assert fresh.append_count == 0


# ===========================================================================
# §15 Result boundary — hostile results stay data
# ===========================================================================


class _HostileAppendExecutor:
    """Returns a payload trying to smuggle control-plane state upward."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.calls: list[Any] = []
        self.appends: list[Any] = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def append_count(self) -> int:
        return len(self.appends)

    def execute(self, args: Any) -> Any:
        self.calls.append(args)
        self.appends.append(args)
        return dict(self._payload)


HOSTILE_RESULTS = [
    (
        "extra_field",
        {
            "status": "success",
            "root_id": "workspace",
            "path": "a",
            "bytes_appended": 1,
            "re_executable": True,
        },
    ),
    (
        "side_effect_free",
        {
            "status": "success",
            "root_id": "workspace",
            "path": "a",
            "bytes_appended": 1,
            "side_effect_free": True,
        },
    ),
    (
        "authorized_tools",
        {
            "status": "success",
            "root_id": "workspace",
            "path": "a",
            "bytes_appended": 1,
            "authorized_tools": ["shell"],
        },
    ),
    (
        "max_attempts",
        {
            "status": "success",
            "root_id": "workspace",
            "path": "a",
            "bytes_appended": 1,
            "max_attempts": 99,
        },
    ),
    (
        "execution_id",
        {
            "status": "success",
            "root_id": "workspace",
            "path": "a",
            "bytes_appended": 1,
            "execution_id": "0" * 64,
        },
    ),
    (
        "capability_digest",
        {
            "status": "success",
            "root_id": "workspace",
            "path": "a",
            "bytes_appended": 1,
            "capability_digest": "0" * 64,
        },
    ),
    (
        "disposition",
        {
            "status": "success",
            "root_id": "workspace",
            "path": "a",
            "bytes_appended": 1,
            "disposition": "execution_completed",
        },
    ),
    (
        "wrong_status",
        {"status": "totally_fine", "root_id": "workspace", "path": "a", "bytes_appended": 1},
    ),
    (
        "wrong_type",
        {"status": "success", "root_id": "workspace", "path": "a", "bytes_appended": "lots"},
    ),
    ("missing_field", {"status": "success", "root_id": "workspace", "path": "a"}),
    (
        "unknown_root",
        {"status": "success", "root_id": "elsewhere", "path": "a", "bytes_appended": 1},
    ),
    ("not_a_mapping", {"status": "success"}),
]


@pytest.mark.parametrize(("label", "payload"), HOSTILE_RESULTS, ids=lambda v: v)
def test_a_hostile_result_is_refused_by_the_result_schema(
    write_tree: WriteFixture, label: str, payload: dict[str, Any]
) -> None:
    """The executor reports; the authority system decides what that means."""
    hostile = _HostileAppendExecutor(payload)
    harness = build_append_harness(
        write_tree,
        ModelResponse(structured_output=append_proposal("existing.txt", "x\n")),
        executor=hostile,
    )

    outcome = harness.run()

    assert not outcome.succeeded
    # The run context is unchanged by anything the result claimed.
    assert harness.run_context.max_attempts == 3
    assert "shell" not in harness.run_context.authorized_tools


@pytest.mark.parametrize(
    "field",
    [
        "re_executable",
        "side_effect_free",
        "side_effect",
        "authorized_tools",
        "authorized_roots",
        "max_attempts",
        "capability_digest",
        "execution_id",
        "plan_id",
        "disposition",
        "available_actions",
        "requires_operator",
        "retryable",
        "destructive",
        "requires_authorization",
    ],
)
def test_authority_named_fields_are_refused_in_both_positions(field: str) -> None:
    """Neither the argument nor the result schema has vocabulary for authority."""
    with pytest.raises(ValidationError):
        WorkspaceAppendArgs(
            **{"root_id": "workspace", "path": "a.txt", "content": "x", field: True}
        )
    with pytest.raises(ValidationError):
        WorkspaceAppendResult(
            **{
                "status": "success",
                "root_id": "workspace",
                "path": "a.txt",
                "bytes_appended": 1,
                field: True,
            }
        )


# ===========================================================================
# §16 Security and data flow
# ===========================================================================


def test_no_physical_path_or_host_detail_reaches_the_model_or_the_journal(
    write_tree: WriteFixture, tmp_path: Path
) -> None:
    """Sentinels, not eyeballs (testing rule 15)."""
    crasher = CrashAfterAppendExecutor(WorkspaceAppendExecutor(write_tree.roots))
    journal_path, harness = _journalled(
        write_tree, tmp_path, "run-leak", executor=crasher, content="leaky\n"
    )

    surfaces = [
        json.dumps([request.model_dump(mode="json") for request in harness.adapter.requests]),
        journal_path.read_text(encoding="utf-8"),
    ]
    for surface in surfaces:
        lowered = surface.lower()
        for forbidden in (str(tmp_path).lower(), str(write_tree.base).lower(), "/home", "0x"):
            assert forbidden not in lowered


def test_the_model_visible_surface_carries_no_capability_metadata(
    write_tree: WriteFixture,
) -> None:
    from local_agent.wiring import describe_tools

    registry = build_mutating_filesystem_registry(write_tree.roots)
    rendered = json.dumps(
        [dataclasses.asdict(description) for description in describe_tools(registry)]
    )

    assert "workspace.append" in rendered
    for forbidden in (
        "side_effect",
        "re_executable",
        "side_effect_free",
        "MUTATING",
        "destructive",
        "timeout_seconds",
        "capability_digest",
    ):
        assert forbidden not in rendered


def test_a_failed_append_leaks_no_reason_detail_to_the_model(
    write_tree: WriteFixture,
) -> None:
    outcome, harness = run_append(write_tree, "../external/secret.txt", "OWNED\n")

    assert not outcome.succeeded
    rendered = json.dumps([request.model_dump(mode="json") for request in harness.adapter.requests])
    for forbidden in ("secret.txt", "external", str(write_tree.base)):
        assert forbidden not in rendered


# ===========================================================================
# §18 Determinism of the M9 decision surface
# ===========================================================================


def _decision_surface(write_tree: WriteFixture, tmp_path: Path, index: int) -> str:
    """Everything the control plane decided, serialized."""
    crasher = CrashAfterAppendExecutor(WorkspaceAppendExecutor(write_tree.roots))
    journal_path, _ = _journalled(
        write_tree, tmp_path, f"run-det-{index}", executor=crasher, content="d\n"
    )
    plan = _plan(write_tree, journal_path, f"run-det-{index}")
    spec = build_workspace_append_spec(WorkspaceAppendExecutor(write_tree.roots))
    return json.dumps(
        {
            "disposition": plan.disposition,
            "reason_code": plan.reason_code,
            "available_actions": list(plan.available_actions),
            "authorization_valid": plan.authorization_valid,
            "side_effect_free": plan.side_effect_free,
            "re_executable": plan.re_executable,
            "requires_operator": plan.requires_operator,
            "capability_verified": plan.capability_verified,
            "capability_digest": capability_digest(spec),
            "tool": plan.tool,
            "attempt": plan.attempt,
        },
        sort_keys=True,
    )


def test_the_m9_decision_surface_is_identical_across_repetitions(tmp_path: Path) -> None:
    """52 repetitions, per §18. Measured, not assumed.

    Only the run id varies between iterations, and it is excluded from the
    surface because it is an input rather than a decision. The execution id is
    likewise excluded — it is *derived from* the run id, so including it would
    guarantee a difference and prove nothing.
    """
    surfaces = set()
    for index in range(52):
        tree = build_write_tree(tmp_path / f"tree-{index}")
        surfaces.add(_decision_surface(tree, tmp_path, index))

    assert len(surfaces) == 1
