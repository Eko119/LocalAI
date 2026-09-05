"""Controller-owned tool registry.

The registry is built once, by trusted application wiring, from a fixed list
of `ToolSpec` objects (see `executors/file_search.py` for the one Milestone 1
tool). There is deliberately no `register()` method and no mutation API of
any kind: the type has no code path that could add or change a tool at
runtime, which is a stronger guarantee than merely refusing to expose one to
the model. Unknown tool names never reach an executor because
`ToolRegistry.get` is the only way the controller resolves a name, and a miss
there ends the run at `TOOL_NOT_FOUND` (see `controller.py`).

Deviation note (see final report): 07-AGENT-IMPLEMENTATION-CONTRACT.md's
`ToolExecutor` Protocol snippet is `async def execute(self, args: BaseModel)
-> ToolResult`. The milestone task's literal `FakeFileSearchExecutor` block is
a *synchronous* method returning a plain `dict`. Milestone-prompt code takes
precedence as the more specific, directly-given directive, so `ToolExecutor`
here is sync and returns `dict[str, Any]`; the controller validates that dict
against the tool's `result_schema` in the VERIFY state rather than trusting a
typed `ToolResult` return.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel


class ToolExecutionError(RuntimeError):
    """Raised by an executor to signal a normalized, non-crashing failure.

    Executors raise this for *expected* operational failures, which the
    controller normalizes to `EXECUTION_FAILED`. Anything else an executor
    raises is a programmer error and is deliberately allowed to propagate
    (spec §"error_handling") instead of being swallowed by a blanket catch.
    """


class ToolExecutor(Protocol):
    """What a tool's executor must implement. See module docstring re: sync/dict."""

    def execute(self, args: BaseModel) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ToolSpec:
    """Everything the controller needs to know about one tool.

    `name` is immutable (frozen dataclass, no setter). `args_schema` and
    `result_schema` are the two ends of the typed boundary around the
    executor — the controller never lets untyped data cross either edge.
    """

    name: str
    args_schema: type[BaseModel]
    executor: ToolExecutor
    timeout_seconds: float
    requires_authorization: bool
    destructive: bool
    result_schema: type[BaseModel]


class ToolRegistry:
    """Immutable name -> ToolSpec lookup. Built once; never mutated after."""

    def __init__(self, tools: tuple[ToolSpec, ...]):
        by_name: dict[str, ToolSpec] = {}
        for spec in tools:
            if spec.name in by_name:
                raise ValueError(f"duplicate tool name in registry: {spec.name!r}")
            by_name[spec.name] = spec
        self._by_name = by_name

    def get(self, name: str) -> ToolSpec | None:
        return self._by_name.get(name)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._by_name)

    def __contains__(self, name: object) -> bool:
        return name in self._by_name
