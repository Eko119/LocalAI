"""Durable journal: integrity, limits, locking, and the corruption matrix.

Every corruption case here must fail closed. Authoritative state is never
silently repaired, and a journal that cannot be fully accounted for is not
partially believed — it is refused.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from local_agent.persistence.journal import (
    JournalLockError,
    RunJournal,
    read_lines,
    read_records,
)
from local_agent.persistence.records import (
    MAX_ARGUMENTS_BYTES,
    MAX_EVENTS_PER_RUN,
    SCHEMA_VERSION,
    ExecutionAuthorized,
    ExecutionCompleted,
    JournalError,
    RunStarted,
    RunTerminal,
    canonical_json,
    checksum,
    derive_execution_id,
    envelope,
    new_run_id,
)

RUN = "run-persist"
ARGS = {"root_id": "workspace", "path": "README.md"}
EID = derive_execution_id(RUN, f"{RUN}-s1", 1, "workspace.read", ARGS)


def authorized(**overrides: object) -> ExecutionAuthorized:
    fields: dict[str, object] = {
        "run_id": RUN,
        "step_id": f"{RUN}-s1",
        "attempt": 1,
        "tool": "workspace.read",
        "arguments": ARGS,
        "execution_id": EID,
        "side_effect_free": True,
    }
    fields.update(overrides)
    return ExecutionAuthorized(**fields)


def write_journal(path: Path, *records: object) -> None:
    with RunJournal(path) as journal:
        for record in records:
            journal.append(record)  # type: ignore[arg-type]


def corrupt(path: Path, line_index: int, transform: object) -> None:
    """Rewrite one journal line through a transform, leaving others intact."""
    lines = read_lines(path)
    lines[line_index] = transform(lines[line_index])  # type: ignore[operator]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Round trip and identity
# ---------------------------------------------------------------------------


def test_records_round_trip_in_sequence_order(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    write_journal(
        path,
        RunStarted(run_id=RUN, max_attempts=3),
        authorized(),
        ExecutionCompleted(run_id=RUN, execution_id=EID, status="succeeded"),
        RunTerminal(run_id=RUN, status="succeeded", attempts=1),
    )

    records = read_records(path)
    assert [seq for seq, _ in records] == [0, 1, 2, 3]
    assert [record.type for _, record in records] == [
        "run_started",
        "execution_authorized",
        "execution_completed",
        "run_terminal",
    ]


def test_execution_identity_is_derived_and_order_independent() -> None:
    """Content-addressed, so argument key order cannot change the identity."""
    a = derive_execution_id(RUN, "s", 1, "t", {"b": 2, "a": 1})
    b = derive_execution_id(RUN, "s", 1, "t", {"a": 1, "b": 2})
    assert a == b and len(a) == 32

    # Every input participates: change any one and the identity changes.
    assert derive_execution_id("other", "s", 1, "t", {"a": 1}) != derive_execution_id(
        RUN, "s", 1, "t", {"a": 1}
    )
    assert derive_execution_id(RUN, "s", 2, "t", {"a": 1}) != derive_execution_id(
        RUN, "s", 1, "t", {"a": 1}
    )
    assert derive_execution_id(RUN, "s", 1, "u", {"a": 1}) != derive_execution_id(
        RUN, "s", 1, "t", {"a": 1}
    )
    assert derive_execution_id(RUN, "s", 1, "t", {"a": 2}) != derive_execution_id(
        RUN, "s", 1, "t", {"a": 1}
    )


def test_run_ids_are_unique_and_key_safe() -> None:
    ids = {new_run_id() for _ in range(500)}
    assert len(ids) == 500
    for value in ids:
        assert value.isalnum()
        # Safe as a filename component: nothing that could redirect a write.
        assert "/" not in value and ".." not in value


@pytest.mark.parametrize("bad", ["../escape", "a/b", "with space", "", "x" * 129, "nul\x00"])
def test_a_run_id_that_could_redirect_a_write_is_rejected(bad: str) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RunStarted(run_id=bad, max_attempts=3)


def test_serialization_is_deterministic() -> None:
    """Equivalent state must produce byte-identical records."""
    first = envelope(authorized(), 7)
    second = envelope(authorized(arguments={"path": "README.md", "root_id": "workspace"}), 7)
    assert first == second
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    # ASCII-escaped, so the bytes do not depend on the writer's locale.
    assert canonical_json({"k": "café"}) == '{"k":"caf\\u00e9"}'


# ---------------------------------------------------------------------------
# Durability boundary and locking
# ---------------------------------------------------------------------------


def test_a_partial_final_line_is_not_a_record(tmp_path: Path) -> None:
    """A crash mid-append leaves a torn line; it was never durable."""
    path = tmp_path / "run.jsonl"
    write_journal(path, RunStarted(run_id=RUN, max_attempts=3), authorized())

    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq": 2, "checksum": "aaaaaaaaaaaaaaaa", "reco')

    assert len(read_records(path)) == 2  # unchanged, and not an error


def test_a_torn_line_in_the_middle_is_corruption_not_truncation(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    write_journal(path, RunStarted(run_id=RUN, max_attempts=3), authorized())
    corrupt(path, 0, lambda line: line[: len(line) // 2])

    with pytest.raises(JournalError) as excinfo:
        read_records(path)
    assert excinfo.value.reason == "journal_line_malformed"


def test_a_second_live_holder_is_refused_rather_than_queued(tmp_path: Path) -> None:
    """Two live recoveries of one run must not both proceed (task §24)."""
    path = tmp_path / "run.jsonl"
    first = RunJournal(path)
    try:
        with pytest.raises(JournalLockError) as excinfo:
            RunJournal(path)
        assert excinfo.value.reason == "journal_locked_by_another_process"
    finally:
        first.close()

    # Once released, the run is recoverable again.
    RunJournal(path).close()


def test_a_reopened_journal_continues_the_sequence(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    write_journal(path, RunStarted(run_id=RUN, max_attempts=3))
    with RunJournal(path) as journal:
        assert journal.sequence == 1
        assert journal.append(authorized()) == 1


def test_appending_to_a_closed_journal_is_refused(tmp_path: Path) -> None:
    journal = RunJournal(tmp_path / "run.jsonl")
    journal.close()
    with pytest.raises(JournalError) as excinfo:
        journal.append(RunStarted(run_id=RUN, max_attempts=3))
    assert excinfo.value.reason == "journal_closed"


# ---------------------------------------------------------------------------
# Resource ceilings (task §25)
# ---------------------------------------------------------------------------


def test_oversized_arguments_are_refused_not_truncated() -> None:
    with pytest.raises(JournalError) as excinfo:
        envelope(authorized(arguments={"path": "x" * (MAX_ARGUMENTS_BYTES + 10)}), 0)
    assert excinfo.value.reason == "arguments_exceed_ceiling"


def test_an_oversized_record_is_refused() -> None:
    from local_agent.persistence import records as records_module

    original = records_module.MAX_RECORD_BYTES
    records_module.MAX_RECORD_BYTES = 50
    try:
        with pytest.raises(JournalError) as excinfo:
            envelope(RunStarted(run_id=RUN, max_attempts=3), 0)
        assert excinfo.value.reason == "record_exceeds_ceiling"
    finally:
        records_module.MAX_RECORD_BYTES = original


def test_the_event_count_ceiling_bounds_the_journal(tmp_path: Path) -> None:
    """Append-only storage must not be unbounded."""
    from local_agent.persistence import records as records_module

    original = records_module.MAX_EVENTS_PER_RUN
    records_module.MAX_EVENTS_PER_RUN = 2
    try:
        path = tmp_path / "run.jsonl"
        with RunJournal(path) as journal:
            journal.append(RunStarted(run_id=RUN, max_attempts=3))
            journal.append(authorized())
            with pytest.raises(JournalError) as excinfo:
                journal.append(ExecutionCompleted(run_id=RUN, execution_id=EID, status="succeeded"))
        assert excinfo.value.reason == "event_count_exceeds_ceiling"
    finally:
        records_module.MAX_EVENTS_PER_RUN = original


def test_the_ceiling_constant_is_bounded() -> None:
    assert 0 < MAX_EVENTS_PER_RUN <= 100_000


# ---------------------------------------------------------------------------
# The corruption matrix (task §14) — every case fails closed
# ---------------------------------------------------------------------------


def _two_record_journal(tmp_path: Path) -> Path:
    path = tmp_path / "run.jsonl"
    write_journal(path, RunStarted(run_id=RUN, max_attempts=3), authorized())
    return path


def _rewrite_record(line: str, **changes: object) -> str:
    """Rewrite a record's body *and* refresh its checksum.

    This is the important half of the adversarial story: it simulates an
    attacker who knows the format, not merely a corrupted byte. The checksum
    stops being the thing that catches them, which is exactly why recovery
    re-derives instead of trusting it.
    """
    payload = json.loads(line)
    payload["record"].update(changes)
    payload["checksum"] = checksum(canonical_json(payload["record"]))
    return canonical_json(payload)


@pytest.mark.parametrize(
    ("label", "transform", "reason"),
    [
        ("malformed_json", lambda line: line[:-3], "journal_line_malformed"),
        ("not_an_object", lambda line: "[1,2,3]", "journal_line_not_an_object"),
        ("empty_object", lambda line: "{}", "journal_envelope_invalid"),
        (
            "missing_checksum",
            lambda line: canonical_json(
                {k: v for k, v in json.loads(line).items() if k != "checksum"}
            ),
            "journal_envelope_invalid",
        ),
        (
            "negative_sequence",
            lambda line: canonical_json({**json.loads(line), "seq": -1}),
            "journal_envelope_invalid",
        ),
        (
            "tampered_body_without_checksum_update",
            lambda line: line.replace('"max_attempts":3', '"max_attempts":999'),
            "record_checksum_mismatch",
        ),
        (
            "unknown_record_type",
            lambda line: _rewrite_record(line, type="grant_everything"),
            "record_type_unknown",
        ),
        (
            "unsupported_schema_version",
            lambda line: _rewrite_record(line, schema_version=SCHEMA_VERSION + 41),
            "record_schema_version_unsupported",
        ),
        (
            "missing_required_field",
            lambda line: _rewrite_record_without(line, "max_attempts"),
            "record_schema_invalid",
        ),
        (
            "unknown_extra_field",
            lambda line: _rewrite_record(line, authorized_everything=True),
            "record_schema_invalid",
        ),
        (
            "impossible_retry_budget",
            lambda line: _rewrite_record(line, max_attempts=0),
            "record_schema_invalid",
        ),
        (
            "negative_retry_budget",
            lambda line: _rewrite_record(line, max_attempts=-5),
            "record_schema_invalid",
        ),
    ],
)
def test_corrupted_records_fail_closed(
    tmp_path: Path, label: str, transform: object, reason: str
) -> None:
    path = _two_record_journal(tmp_path)
    corrupt(path, 0, transform)

    with pytest.raises(JournalError) as excinfo:
        read_records(path)
    assert excinfo.value.reason == reason, label


def _rewrite_record_without(line: str, field: str) -> str:
    payload = json.loads(line)
    payload["record"].pop(field, None)
    payload["checksum"] = checksum(canonical_json(payload["record"]))
    return canonical_json(payload)


def test_a_duplicate_sequence_number_is_refused(tmp_path: Path) -> None:
    path = _two_record_journal(tmp_path)
    lines = read_lines(path)
    duplicated = canonical_json({**json.loads(lines[1]), "seq": 0})
    path.write_text(lines[0] + "\n" + duplicated + "\n", encoding="utf-8")

    with pytest.raises(JournalError) as excinfo:
        read_records(path)
    assert excinfo.value.reason == "journal_duplicate_sequence"


def test_a_sequence_gap_is_refused(tmp_path: Path) -> None:
    path = _two_record_journal(tmp_path)
    lines = read_lines(path)
    gapped = canonical_json({**json.loads(lines[1]), "seq": 7})
    path.write_text(lines[0] + "\n" + gapped + "\n", encoding="utf-8")

    with pytest.raises(JournalError) as excinfo:
        read_records(path)
    assert excinfo.value.reason == "journal_sequence_gap"


def test_invalid_utf8_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    write_journal(path, RunStarted(run_id=RUN, max_attempts=3))
    path.write_bytes(path.read_bytes() + b"\xff\xfe not utf-8\n")

    with pytest.raises(JournalError) as excinfo:
        read_records(path)
    assert excinfo.value.reason == "journal_not_utf8"


def test_a_missing_journal_is_empty_not_an_error(tmp_path: Path) -> None:
    assert read_records(tmp_path / "absent.jsonl") == []


def test_the_corruption_harness_leaves_a_valid_journal_valid(tmp_path: Path) -> None:
    """Guard against a harness that fails everything for the wrong reason."""
    path = _two_record_journal(tmp_path)
    corrupt(path, 0, lambda line: line)  # identity transform
    assert len(read_records(path)) == 2
