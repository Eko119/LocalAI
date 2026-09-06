"""The capability contract: what a tool must satisfy to be admissible.

A capability is the only way anything outside this package's control plane ever
happens. So the question this module answers is not "how do I add a tool" but
**"what must be true before a capability is allowed to exist, and what stops
the capability from becoming an authority itself?"**

Three mechanisms answer it, in this order:

1. **Admission** (`admit`). A `ToolSpec` is a plain frozen dataclass and
   dataclasses do not validate, so construction alone proves nothing. Nothing
   reaches a registry without passing `admit`, which checks the name, the
   schemas, the executor protocol, the resource bounds, and the coherence rules
   between the declared properties — including that a destructive capability
   must require authorization, which is the one combination that would
   otherwise silently skip a grant check.
2. **Immutability**. The spec is frozen, the registry's map is a read-only
   proxy, and the registry refuses attribute rebinding. The honest limit is
   stated in `ToolRegistry`: in-process Python has no true tamper barrier, so
   what this buys is the absence of a *sanctioned* path and the detection of
   drift, not immunity from `object.__setattr__`.
3. **Identity** (`capability_digest`). Immutability cannot cover what a spec
   only *references* — `args_schema` and `result_schema` are classes, and
   Python classes are mutable. Rather than pretend otherwise, the capability is
   content-addressed over its declared behaviour, so a definition that changes
   after an execution was authorized is *detectable* by recovery even though it
   was not preventable.

Deviation note (see Milestone 1's report): 07-AGENT-IMPLEMENTATION-CONTRACT.md's
`ToolExecutor` Protocol snippet is `async def execute(self, args: BaseModel)
-> ToolResult`. The milestone task's literal `FakeFileSearchExecutor` block is
a *synchronous* method returning a plain `dict`. Milestone-prompt code takes
precedence as the more specific, directly-given directive, so `ToolExecutor`
here is sync and returns `dict[str, Any]`; the controller validates that dict
against the tool's `result_schema` in the VERIFY state rather than trusting a
typed `ToolResult` return.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, unique
from types import MappingProxyType
from typing import Any, Protocol

from pydantic import BaseModel

from .persistence.records import canonical_json

# Bumped when the *meaning* of a capability's declared properties changes. It
# is part of the digest, so a contract change makes every previously recorded
# digest stop matching rather than silently comparing across versions.
CAPABILITY_SCHEMA_VERSION = 1

# A capability name is an audit key, a model-visible label, and a journal
# value. Bounded and restricted to a dotted lower-snake namespace, so it cannot
# become a path, carry whitespace, or vary by case.
MAX_TOOL_NAME_LENGTH = 64

# An upper bound on what any capability may declare for itself. A per-run
# ceiling belongs to `RunContext`; this is the structural maximum, in the same
# relationship as `contracts.MAX_PATH_LENGTH` to `FilesystemLimits`.
MAX_TIMEOUT_SECONDS = 300.0
MIN_TIMEOUT_SECONDS = 0.001


class ToolExecutionError(RuntimeError):
    """Raised by an executor to signal a normalized, non-crashing failure.

    Executors raise this for *expected* operational failures, which the
    controller normalizes to `EXECUTION_FAILED`. Anything else an executor
    raises is a programmer error and is deliberately allowed to propagate
    (spec §"error_handling") instead of being swallowed by a blanket catch.

    `reason` is a stable, controller-private slug for the audit stream. It
    must never contain a path, a host detail, or an OS message; the
    exception's own message is never forwarded to the model.
    """

    def __init__(self, message: str = "", *, reason: str = "execution_failed") -> None:
        self.reason = reason
        super().__init__(message)


class ToolDenialError(RuntimeError):
    """Raised by an executor when the request is not permitted, not merely failing.

    Some authorization facts cannot be established without touching the
    resource: whether a path stays inside its root can only be known after
    the physical path is resolved, and resolution is the executor's job, not
    the controller's. This exception is how an executor reports that
    discovery.

    It can only ever *deny*. An executor has no way to grant authority it was
    not wired with, so admitting this direction is fail-closed: the controller
    normalizes it to the same non-retryable `POLICY_DENIED` the AUTHORIZE and
    POLICY_CHECK gates emit, with the same opaque message. The model cannot
    tell which of the three said no.

    `reason` is a controller-private slug for the audit stream and must never
    carry a physical path.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class CapabilityInadmissible(ValueError):
    """A `ToolSpec` was refused admission. Always fatal; never repaired.

    Raised at wiring time, by trusted code, before any run exists. That timing
    is the point: an inadmissible capability is a programming error caught at
    assembly, not a condition the controller has to defend against later.

    `reason` is a stable slug so the admission matrix can be tested by outcome
    rather than by message text.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@unique
class SideEffect(Enum):
    """How the world changes when a capability runs, and what repeating costs.

    Three values rather than a boolean, because two genuinely different
    questions were being answered by one flag:

    * *did anything observable happen?* — which decides what an ambiguous
      crash even means, and what an operator is being told;
    * *is running it again safe?* — which decides whether the controller may
      retry, in a live run or after recovery.

    A boolean can answer one of those. Collapsing them was survivable only
    because every capability shipped so far is `NONE`, where both answers
    coincide. The first genuinely side-effecting capability separates them,
    and the contract has to be able to say so before that capability exists.
    """

    # No observable effect outside the process. Reading a file is the example:
    # running it twice is indistinguishable from running it once.
    NONE = "none"
    # Has an effect, but the end state after N runs equals the end state after
    # one. Writing a fixed value to a fixed key is the example.
    IDEMPOTENT = "idempotent"
    # Has an effect that compounds. Appending, sending, charging, deleting a
    # generation. Running it twice is not running it once, and no amount of
    # controller machinery can make it so.
    MUTATING = "mutating"


class ToolExecutor(Protocol):
    """What a tool's executor must implement. See module docstring re: sync/dict."""

    def execute(self, args: BaseModel) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ToolSpec:
    """Everything the controller needs to know about one capability.

    Frozen, and every field is authority: the schemas bound what may cross
    either edge of the executor, `requires_authorization` and `destructive`
    feed the gates, `side_effect` decides repetition, and `executor` is the
    only thing that acts. Nothing here is ever derived from model output; a
    spec is built by trusted wiring and admitted by `admit` before use.

    Note what is *not* here: no grants, no budget, no roots, no ceilings that
    a run owns. A capability declares what it is; `RunContext` decides what
    this run may do with it. Keeping those apart is why a capability cannot
    widen its own authority by declaring itself more privileged.
    """

    name: str
    args_schema: type[BaseModel]
    executor: ToolExecutor
    timeout_seconds: float
    requires_authorization: bool
    destructive: bool
    result_schema: type[BaseModel]
    # Fail closed: a capability nobody has classified is assumed to compound.
    # The model can never set this — `ToolSpec` is frozen, built by trusted
    # wiring, and nothing in a proposal reaches it.
    side_effect: SideEffect = SideEffect.MUTATING

    @property
    def side_effect_free(self) -> bool:
        """Whether running this produces no observable effect at all.

        Derived, not stored, so it cannot disagree with `side_effect`. This is
        the property Milestone 5 persists and Milestone 6 re-checks: for an
        *ambiguous* execution it answers "did anything happen either way".
        """
        return self.side_effect is SideEffect.NONE

    @property
    def re_executable(self) -> bool:
        """Whether the controller may run this capability again.

        True for `NONE` and `IDEMPOTENT` and false for `MUTATING` — which is
        deliberately *not* the same question as `side_effect_free`. An
        idempotent capability is safe to repeat while emphatically having had
        an effect, and a system that equated the two would either refuse safe
        retries or permit compounding ones.
        """
        return self.side_effect in (SideEffect.NONE, SideEffect.IDEMPOTENT)


def _validate_name(name: str) -> None:
    """A dotted lower-snake identifier, bounded, with no path or case tricks."""
    if not name:
        raise CapabilityInadmissible("capability_name_empty")
    if len(name) > MAX_TOOL_NAME_LENGTH:
        raise CapabilityInadmissible("capability_name_too_long")
    for segment in name.split("."):
        if not segment:
            raise CapabilityInadmissible("capability_name_empty_segment")
        if not (segment[0].isascii() and segment[0].islower()):
            raise CapabilityInadmissible("capability_name_segment_start_invalid")
        for character in segment:
            legal = character == "_" or (
                character.isascii() and (character.islower() or character.isdigit())
            )
            if not legal:
                raise CapabilityInadmissible("capability_name_character_invalid")


def _validate_schema(schema: object, reason: str) -> None:
    if not isinstance(schema, type) or not issubclass(schema, BaseModel):
        raise CapabilityInadmissible(reason)


def admit(spec: ToolSpec) -> ToolSpec:
    """Check a capability against the contract, or refuse it.

    Returns the spec unchanged when it passes, so a builder can wrap its own
    construction in it and fail at definition time. It is deliberately *not* a
    stamp: an "already admitted" marker would be a field, and a field can be
    carried forward by `dataclasses.replace` onto a spec whose properties have
    since changed — which is exactly how a destructive capability would end up
    marked as checked while never having been. `ToolRegistry` therefore calls
    this itself, unconditionally, on every entry.

    The coherence rules at the end are the interesting part. Each is a
    combination that is individually well-typed and jointly meaningless, and
    each would fail silently rather than loudly:

    * **destructive but unauthorized** — `policy.authorize` only consults the
      run's tool grants when `requires_authorization` is set, so this spec
      would let a destructive capability run for a run holding no grant at
      all. Measured, not theorised: `authorize` returns `allowed=True` for it.
    * **destructive but not mutating** — a capability that destroys something
      and claims repeating it is free is describing two different tools.
    """
    _validate_name(spec.name)
    _validate_schema(spec.args_schema, "capability_args_schema_not_a_model")
    _validate_schema(spec.result_schema, "capability_result_schema_not_a_model")

    if not isinstance(spec.side_effect, SideEffect):
        raise CapabilityInadmissible("capability_side_effect_not_classified")

    if not isinstance(spec.timeout_seconds, int | float) or isinstance(spec.timeout_seconds, bool):
        raise CapabilityInadmissible("capability_timeout_not_a_number")
    if not MIN_TIMEOUT_SECONDS <= spec.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise CapabilityInadmissible("capability_timeout_out_of_range")

    if not isinstance(spec.requires_authorization, bool):
        raise CapabilityInadmissible("capability_requires_authorization_not_a_bool")
    if not isinstance(spec.destructive, bool):
        raise CapabilityInadmissible("capability_destructive_not_a_bool")

    execute = getattr(spec.executor, "execute", None)
    if not callable(execute):
        raise CapabilityInadmissible("capability_executor_not_callable")

    if spec.destructive and not spec.requires_authorization:
        raise CapabilityInadmissible("capability_destructive_without_authorization")
    if spec.destructive and spec.side_effect is not SideEffect.MUTATING:
        raise CapabilityInadmissible("capability_destructive_but_not_mutating")

    return spec


def capability_digest(spec: ToolSpec) -> str:
    """Content-address a capability's declared behaviour.

    The same technique as execution identity and plan identity, applied to the
    one part of a capability that immutability cannot protect. `args_schema`
    and `result_schema` are classes, and a class's fields, config and compiled
    validator can all be replaced at runtime — measured, not assumed. Freezing
    that is not available in Python, so the contract makes the change
    *detectable* instead: the digest covers the JSON schema of both ends, so a
    widened argument schema or an altered result shape produces a different
    capability.

    The executor is deliberately absent. It is an implementation of the
    capability, not the capability: a test that substitutes a spy for the
    production executor must not change the capability's identity, or every
    recovery test would be exercising a different capability from the one that
    ships. The cost is stated plainly — the digest does not detect an executor
    swap, and nothing here claims it does.
    """
    return hashlib.sha256(
        canonical_json(
            {
                "schema_version": CAPABILITY_SCHEMA_VERSION,
                "name": spec.name,
                "args_schema": spec.args_schema.model_json_schema(),
                "result_schema": spec.result_schema.model_json_schema(),
                "requires_authorization": spec.requires_authorization,
                "destructive": spec.destructive,
                "side_effect": spec.side_effect.value,
                "timeout_seconds": float(spec.timeout_seconds),
            }
        ).encode("utf-8")
    ).hexdigest()[:32]


class ToolRegistry:
    """Immutable name -> ToolSpec lookup. Built once; never mutated after.

    Three properties, and one honest limitation.

    **Admission.** Every spec is put through `admit` on the way in, every
    time, so the registry cannot hold a capability that failed the contract.
    There is deliberately no "already checked" marker to trust: a marker is a
    field, and `dataclasses.replace` would carry it onto a spec whose
    properties had since changed. Re-checking is cheap and unforgeable.

    **No mutation API.** There is no `register`, `replace`, `remove`, or
    `update`. Duplicate names are refused at construction rather than
    last-one-wins, because silent replacement is how a capability would come to
    mean something different from what an earlier run authorized.

    **No accidental mutation.** The map is a `MappingProxyType`, so
    `registry.names` and lookups cannot be written through, and `__setattr__`
    refuses rebinding after construction. Before Milestone 7 both of those were
    possible: `_by_name["evil"] = spec` and `_by_name = {}` both worked.

    **The limitation, stated rather than glossed.** In-process Python has no
    real tamper barrier — `object.__setattr__` reaches past any guard, and the
    schema *classes* a spec points at remain mutable no matter what this object
    does. So this is not immunity. What it is: the removal of every sanctioned
    path, so an accidental or careless mutation fails loudly, plus
    `capability_digest`, so a determined one is detectable after the fact.
    """

    __slots__ = ("_by_name", "_frozen")

    # Annotated, not assigned: `__slots__` forbids class attributes, and the
    # values are installed through `object.__setattr__` past the guard below.
    _by_name: Mapping[str, ToolSpec]
    _frozen: bool

    def __init__(self, tools: tuple[ToolSpec, ...]):
        by_name: dict[str, ToolSpec] = {}
        for spec in tools:
            if not isinstance(spec, ToolSpec):
                raise CapabilityInadmissible("registry_entry_not_a_tool_spec")
            admit(spec)
            if spec.name in by_name:
                raise CapabilityInadmissible("registry_duplicate_capability_name")
            by_name[spec.name] = spec
        object.__setattr__(self, "_by_name", MappingProxyType(by_name))
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_frozen", False):
            raise AttributeError(f"ToolRegistry is immutable; cannot set {name!r}")
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"ToolRegistry is immutable; cannot delete {name!r}")

    def get(self, name: str) -> ToolSpec | None:
        return self._by_name.get(name)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._by_name)

    @property
    def entries(self) -> Mapping[str, ToolSpec]:
        """Read-only view of the whole map, for wiring and inspection."""
        return self._by_name

    def digests(self) -> Mapping[str, str]:
        """Every admitted capability's content address, by name.

        Recomputed on each call rather than cached, deliberately: a cached
        digest would keep reporting the value a mutated schema used to have,
        which is the opposite of what this exists for.
        """
        return MappingProxyType(
            {name: capability_digest(spec) for name, spec in self._by_name.items()}
        )

    def __contains__(self, name: object) -> bool:
        return name in self._by_name
