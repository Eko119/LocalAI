"""The append-only run journal — the only module that touches durable storage.

`tests/test_architecture.py` enforces that: every other production module,
including the controller that *uses* the journal, still fails the build if it
acquires a filesystem or I/O import. The grant is per module, as the
filesystem grant was in Milestone 2 and the network grant in Milestone 3.

**Why an append-only text journal rather than a database.** Runs are bounded —
three attempts by default, a handful of durable records each — so a snapshot
layer would optimize nothing and add a second representation that could
disagree with the first. A transparent line-per-record format also means the
adversarial recovery tests corrupt and forge *this* format and exercise *this*
validation, rather than exercising SQLite's. `sqlite3` is equally
dependency-free, and would have been the right answer at a scale this project
does not have.

**The durability boundary, stated precisely.** A record is durable when its
line has been written, `flush()`ed out of Python's buffer, and `fsync()`ed to
the storage device, and the append returns only after that. A crash before
`fsync` returns may lose the record; a crash during the write may leave a
partial final line, which the reader detects and refuses to treat as a record.
No stronger claim is made: this code does not fsync the containing directory,
so on some filesystems a crash immediately after file *creation* could lose
the file entry itself.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from typing import IO, Self

from . import records as records_module
from .records import (
    DurableRecord,
    EnvelopedRecord,
    JournalError,
    envelope,
)


class JournalLockError(JournalError):
    """Another live process holds this run's journal.

    Distinct from corruption: the journal is fine, someone else is using it.
    Raised rather than waited on, so a second recovery fails loudly instead of
    silently duplicating the first (task §24).
    """


class RunJournal:
    """One append-only journal for one run.

    The lock is an advisory `flock` held for the journal's lifetime. That
    choice matters for crash recovery specifically: the kernel releases a
    `flock` when the holding process dies, so a crashed run's journal is
    immediately recoverable, while two *live* recoveries cannot both proceed.
    A lock file created with `O_EXCL` would have had the opposite and wrong
    behaviour — a crash would leave a stale lock that blocks recovery forever.
    """

    def __init__(self, path: Path | str, *, lock: bool = True) -> None:
        self._path = Path(path)
        self._handle: IO[str] | None = None
        self._seq = 0
        self._locked = False
        if lock:
            self._acquire()

    # -- lifecycle --------------------------------------------------------

    def _acquire(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        handle = self._path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise JournalLockError("journal_locked_by_another_process") from exc
        self._handle = handle
        self._locked = True
        # Continue the existing sequence rather than restarting it, so a
        # recovered run's records keep a single monotonic ordering.
        self._seq = len(read_lines(self._path))

    def close(self) -> None:
        handle = self._handle
        if handle is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()
        self._handle = None
        self._locked = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def sequence(self) -> int:
        return self._seq

    def records(self) -> list[tuple[int, DurableRecord]]:
        """Read back this run's durable records, fully verified.

        Exists so the controller never has to hold a path. Reading is a
        filesystem operation and this is the module that holds that grant;
        handing the caller a `Path` to open would move the capability one layer
        up, which is exactly what the per-module grant exists to prevent.
        """
        return read_records(self._path)

    # -- append -----------------------------------------------------------

    def append(self, record: DurableRecord) -> int:
        """Durably append one record; return its sequence number.

        Returns only after `fsync`, so a caller that has seen this return may
        rely on the record surviving a crash. That is the whole contract, and
        it is why the controller calls this *before* invoking an executor.
        """
        if self._handle is None:
            raise JournalError("journal_closed")
        if self._seq >= records_module.MAX_EVENTS_PER_RUN:
            raise JournalError("event_count_exceeds_ceiling")

        seq = self._seq
        line = envelope(record, seq)

        handle = self._handle
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())

        self._seq = seq + 1
        return seq


def read_lines(path: Path | str) -> list[str]:
    """Every complete line in the journal, dropping a partial trailing line.

    A partial final line is the signature of a crash mid-append. It is dropped
    rather than repaired: the record it would have become was never durable,
    so the correct interpretation is that it does not exist. A partial line
    anywhere *other* than the end is corruption, and `read_records` rejects it
    because it will not parse.
    """
    target = Path(path)
    if not target.exists():
        return []
    text = target.read_text(encoding="utf-8", errors="strict")
    if not text:
        return []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # the trailing newline of a complete final record
    elif lines:
        lines.pop()  # an unterminated final line: never durable, so not a record
    return lines


def read_records(path: Path | str) -> list[tuple[int, DurableRecord]]:
    """Read, verify, and order every durable record.

    Fails closed on anything it cannot fully account for: malformed JSON, a
    checksum mismatch, an unknown record type, an unsupported schema version,
    a duplicate sequence number, or a gap. Ordering comes from the recorded
    sequence, never from file position.
    """
    import json

    from .records import canonical_json  # noqa: F401 - re-exported for symmetry

    records: list[tuple[int, DurableRecord]] = []
    seen: set[int] = set()

    try:
        lines = read_lines(path)
    except UnicodeDecodeError as exc:
        raise JournalError("journal_not_utf8") from exc

    if len(lines) > records_module.MAX_EVENTS_PER_RUN:
        raise JournalError("event_count_exceeds_ceiling")

    for line in lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise JournalError("journal_line_malformed") from exc
        if not isinstance(payload, dict):
            raise JournalError("journal_line_not_an_object")

        from pydantic import ValidationError

        try:
            enveloped = EnvelopedRecord.model_validate(payload)
        except ValidationError as exc:
            raise JournalError("journal_envelope_invalid") from exc

        if enveloped.seq in seen:
            raise JournalError("journal_duplicate_sequence")
        seen.add(enveloped.seq)

        records.append((enveloped.seq, enveloped.verify()))

    records.sort(key=lambda item: item[0])
    for expected, (seq, _) in enumerate(records):
        if seq != expected:
            raise JournalError("journal_sequence_gap")

    return records
