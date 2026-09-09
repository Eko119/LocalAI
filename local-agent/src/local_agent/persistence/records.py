"""Typed, versioned durable records — and the identity of an execution.

Everything here is a persistence *boundary* type, treated with the same
suspicion as the model boundary in `contracts.py`: frozen, `extra="forbid"`,
explicitly versioned. A record read back from disk is untrusted input, because
a local file is not a trust domain — it can be edited by anything running as
this user, and it can be truncated by a crash.

**What defends against a tampered journal is not the checksum.** The checksum
detects accidental corruption and truncation; an attacker who can rewrite a
record can recompute it, and this module does not pretend otherwise (there is
no key to authenticate with, and inventing one without a threat model to hold
it would be theatre). What actually defends the controller is that recovery
re-derives and re-validates: the execution identity is recomputed from the
run's own state and compared, arguments are re-validated against the live
registry's schema, transitions are re-checked against the transition table,
and the budget is re-checked against `RunContext`. A forged record has to
satisfy all of that, and a record that disagrees fails closed.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# Bumped whenever a record's meaning changes. A journal written by a different
# schema version is not silently reinterpreted — recovery refuses it.
SCHEMA_VERSION = 1

# Resource ceilings. Persistence is append-only, so it needs explicit bounds
# or it becomes unbounded storage (task §25). All are rejections, never silent
# truncation of authoritative data.
MAX_EVENTS_PER_RUN = 1_000
MAX_RECORD_BYTES = 65_536
MAX_ARGUMENTS_BYTES = 16_384

# Milestone 6 ceilings for the operator control plane. An operator decision is
# durable, so an unbounded number of them is unbounded storage, and an
# unbounded reason string is an unbounded field in an append-only file.
MAX_OPERATOR_DECISIONS_PER_RUN = 20

# An operator-supplied reason is a *stable slug*, not prose. The charset is the
# enforcement: with no spaces, no punctuation, and no uppercase, the field
# structurally cannot carry a sentence, an instruction, or a prompt-injection
# payload. That is a stronger property than filtering one, and it is why the
# operator gets a code rather than a free-text field (task 15/19).
REASON_CODE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"

# A run id must be safe to use as a filename component: the journal for a run
# is named after it, and a value containing "/" or ".." would otherwise choose
# where the journal is written. Bounded, and restricted to a key-safe charset.
RUN_ID_PATTERN = r"^[A-Za-z0-9._-]{1,128}$"


def new_run_id() -> str:
    """Generate a run identifier.

    Random, not derived and not a timestamp: two runs started in the same
    millisecond must not collide, and a counter would need durable state of
    its own to be unique across restarts. Nothing about it is model-derived —
    the model never supplies, influences, or sees a run id.

    Production identity is deliberately *not* deterministic. Tests inject
    explicit run ids rather than seeding this, so the determinism suite never
    depends on weakening real identity generation.
    """
    return uuid.uuid4().hex


RecordType = Literal[
    "run_started",
    "execution_authorized",
    "execution_completed",
    "operator_decision",
    "run_terminal",
]

# What an operator may decide about a recovery plan. Deliberately a closed
# set of controller-understood actions rather than a string the controller
# interprets: an unknown action has no branch to reach, so it fails closed at
# the schema rather than at a dispatch table someone might later widen.
#
# `inspect` is absent on purpose. Inspection persists nothing and decides
# nothing, so it is a read on the operator API rather than a durable decision.
OperatorAction = Literal[
    # Re-run the *original* authorized execution. Offered only when the
    # controller has established that repeating it adds no further effect.
    "resume",
    # Stop the run. Terminal, and explicitly not a tool failure.
    "abort",
    # Close a run the controller cannot complete. Terminal.
    "terminalize",
    # Decline this plan without ending the run. Non-terminal, recorded.
    "reject_recovery",
    # Note that the plan was seen. Non-terminal, recorded, grants nothing.
    "acknowledge",
]

# The outcome of one physical execution attempt, as the controller observed it.
ExecutionStatus = Literal["succeeded", "failed"]


class _Record(BaseModel):
    """Base for durable records: frozen, closed, and versioned."""

    model_config = ConfigDict(extra="forbid", frozen=True)


def canonical_json(payload: Any) -> str:
    """Serialize deterministically.

    Sorted keys, no incidental whitespace, and `ensure_ascii=True` so the
    bytes on disk do not depend on the writer's locale or terminal encoding.
    Equivalent controller state must produce byte-identical output, because
    the checksum and the deterministic-fingerprint tests both depend on it.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def derive_execution_id(
    run_id: str, step_id: str, attempt: int, tool: str, arguments: dict[str, Any]
) -> str:
    """Content-address one authorized execution.

    Derived rather than random, and that is the point: recovery can recompute
    it from the run's own state and compare. A journal whose `execution_id`
    does not match the tool and arguments recorded beside it has been altered,
    and recovery rejects it without needing a secret.

    Derived from controller-owned values only. The model contributes the
    *proposal*, but by the time this is computed the proposal has been
    schema-validated, authorized, and policy-checked, and the arguments are
    the canonical typed form rather than the model's raw text.
    """
    material = canonical_json(
        {
            "run_id": run_id,
            "step_id": step_id,
            "attempt": attempt,
            "tool": tool,
            "arguments": arguments,
        }
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def derive_plan_id(material: dict[str, Any]) -> str:
    """Content-address one recovery plan.

    The same technique as `derive_execution_id`, for the same reason: the
    controller recomputes a plan's identity from the journal every time, so an
    operator cannot construct a plan of their own and have it believed. A
    decision names a `plan_id`; if that id does not equal the id the
    controller just derived from the records, the decision is refused.

    It also makes staleness structural rather than a rule someone has to
    remember to apply. The material includes the number of decisions already
    recorded, so recording *any* decision changes the plan's identity and
    every earlier approval stops matching — an approval cannot be replayed
    against the plan it created, let alone a later one.
    """
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:32]


def checksum(payload: str) -> str:
    """Integrity check over a record's canonical body.

    Detects truncation and accidental corruption. It is explicitly *not* a
    tamper seal — see the module docstring.
    """
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


class RunStarted(_Record):
    """Opens a run. Records the budget so recovery cannot be told a larger one."""

    type: Literal["run_started"] = "run_started"
    schema_version: int = SCHEMA_VERSION
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    max_attempts: int = Field(ge=1, le=100)
    # Milestone 10. Persisted for the same reason `max_attempts` is: recovery
    # re-validates the run's authority against the live `RunContext` and must
    # be able to see the composition ceiling the run was actually started
    # under. Without it a recovered run could compose past a ceiling that had
    # since been narrowed, which is the "take a budget from the file" mistake
    # in reverse — the file does not grant the ceiling, it is checked against
    # the live one, and disagreement is fatal.
    #
    # Defaulted to 1 so a journal written before this field existed still
    # parses, and 1 is also the live default, so such a journal validates
    # rather than failing spuriously.
    max_executions: int = Field(default=1, ge=1, le=1000)


class ExecutionAuthorized(_Record):
    """Write-ahead record: every gate passed, execution has *not* yet happened.

    Persisted and flushed before the executor is invoked. That ordering is
    what makes the dangerous crash window detectable at all: a journal holding
    this record with no matching completion means a physical execution may or
    may not have occurred.
    """

    type: Literal["execution_authorized"] = "execution_authorized"
    schema_version: int = SCHEMA_VERSION
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    step_id: str = Field(min_length=1, max_length=128)
    attempt: int = Field(ge=1, le=100)
    tool: str = Field(min_length=1, max_length=128)
    # The canonical, already-validated arguments — not the model's raw text.
    arguments: dict[str, Any]
    execution_id: str = Field(min_length=32, max_length=32)
    # Copied from the controller-owned ToolSpec, never from model output. It
    # decides whether an ambiguous crash may be resolved by re-execution.
    side_effect_free: bool
    # Milestone 7. The content address of the capability *as it was defined
    # when this execution was authorized*. Optional because journals written
    # before capability digests existed are still readable: absent means "not
    # verifiable", which recovery reports rather than treating as verified.
    #
    # Like every other digest in this codebase it detects drift, not tampering
    # — an attacker who can rewrite the record can recompute this too. What it
    # catches is the case nothing else could: a capability whose *definition*
    # changed underneath an authorized execution, where the arguments still
    # validate and the execution identity still re-derives.
    capability_digest: str | None = Field(default=None, min_length=32, max_length=32)


class ExecutionCompleted(_Record):
    """Closes the ambiguity window: this execution physically finished.

    Deliberately records the *outcome*, not the payload. Tool output can be
    large, can contain file contents, and is not needed to reconstruct
    controller state — recovery resumes the run rather than replaying results.
    """

    type: Literal["execution_completed"] = "execution_completed"
    schema_version: int = SCHEMA_VERSION
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    execution_id: str = Field(min_length=32, max_length=32)
    status: ExecutionStatus
    # A controller-private slug, as used everywhere else in the audit stream.
    reason: str | None = Field(default=None, max_length=128)


class OperatorDecisionRecorded(_Record):
    """One explicit operator decision about one controller-generated plan.

    Durable because the decision is authority-adjacent: it is the evidence
    that a human was asked and answered, and the thing that stops the same
    approval being used twice. It is deliberately *not* an authorization —
    the controller re-derives every execution fact for itself and re-runs
    every gate before acting, so this record grants nothing on its own.

    Note what is absent: no operator identity, no free text, no host detail,
    no plan body. The project has no authentication model to attribute a
    decision to (see docs/milestone-6-decisions.md), and inventing an
    unauthenticated `operator` field would record a claim while implying a
    verified fact.
    """

    type: Literal["operator_decision"] = "operator_decision"
    schema_version: int = SCHEMA_VERSION
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    # Monotonic per run, and strictly increasing. This is what bounds duplicate
    # resumes: a decision at or below the highest recorded sequence is refused,
    # so one approval authorizes at most one resume attempt.
    decision_sequence: int = Field(ge=1, le=MAX_OPERATOR_DECISIONS_PER_RUN)
    action: OperatorAction
    # The plan this decision was made about, as the controller derived it.
    plan_id: str = Field(min_length=32, max_length=32)
    # The execution the plan concerned, when it concerned one at all.
    expected_execution_id: str | None = Field(default=None, min_length=32, max_length=32)
    reason_code: str = Field(pattern=REASON_CODE_PATTERN)


class RunTerminal(_Record):
    """The run ended. Recovery must never restart execution past this.

    `aborted` is distinct from `failed` on purpose. A failure is something the
    tool or the model did; an abort is something the operator decided, and
    collapsing the two would lose the difference between "this went wrong" and
    "a human stopped it" in the only record that survives the process.
    """

    type: Literal["run_terminal"] = "run_terminal"
    schema_version: int = SCHEMA_VERSION
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    status: Literal["succeeded", "failed", "aborted"]
    code: str | None = Field(default=None, max_length=64)
    attempts: int = Field(ge=1, le=100)


DurableRecord = (
    RunStarted | ExecutionAuthorized | ExecutionCompleted | OperatorDecisionRecorded | RunTerminal
)

_RECORD_TYPES: dict[str, type[_Record]] = {
    "run_started": RunStarted,
    "execution_authorized": ExecutionAuthorized,
    "execution_completed": ExecutionCompleted,
    "operator_decision": OperatorDecisionRecorded,
    "run_terminal": RunTerminal,
}


class JournalError(Exception):
    """A durable record could not be trusted. Always fatal to recovery."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class EnvelopedRecord(_Record):
    """One line of the journal: sequence, checksum, and the record body.

    The sequence number is controller-assigned and monotonic. Ordering is not
    inferred from file position, because a truncated or reordered file would
    otherwise silently reorder history.
    """

    seq: int = Field(ge=0)
    checksum: str = Field(min_length=16, max_length=16)
    record: dict[str, Any]

    def verify(self) -> DurableRecord:
        """Re-check integrity, then parse into the typed record.

        Unknown record types fail closed rather than being skipped: a journal
        containing something this version does not understand is a journal
        this version must not act on.
        """
        if checksum(canonical_json(self.record)) != self.checksum:
            raise JournalError("record_checksum_mismatch")

        raw_type = self.record.get("type")
        if not isinstance(raw_type, str) or raw_type not in _RECORD_TYPES:
            raise JournalError("record_type_unknown")

        version = self.record.get("schema_version")
        if version != SCHEMA_VERSION:
            raise JournalError("record_schema_version_unsupported")

        from pydantic import ValidationError

        try:
            parsed = _RECORD_TYPES[raw_type].model_validate(self.record)
        except ValidationError as exc:
            raise JournalError("record_schema_invalid") from exc

        assert isinstance(
            parsed,
            RunStarted
            | ExecutionAuthorized
            | ExecutionCompleted
            | OperatorDecisionRecorded
            | RunTerminal,
        )
        return parsed


def envelope(record: DurableRecord, seq: int) -> str:
    """Serialize one record as a single journal line, with integrity.

    Raises rather than truncating when a ceiling is exceeded: silently
    shortening authoritative state is worse than refusing to write it.
    """
    body = record.model_dump(mode="json")

    if isinstance(record, ExecutionAuthorized):
        argument_bytes = len(canonical_json(record.arguments).encode("utf-8"))
        if argument_bytes > MAX_ARGUMENTS_BYTES:
            raise JournalError("arguments_exceed_ceiling")

    line = canonical_json({"seq": seq, "checksum": checksum(canonical_json(body)), "record": body})
    if len(line.encode("utf-8")) > MAX_RECORD_BYTES:
        raise JournalError("record_exceeds_ceiling")
    return line
