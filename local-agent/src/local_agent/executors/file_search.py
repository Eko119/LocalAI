"""Deterministic in-memory file-search executor (spec 07 §3, 04 Phase 2).

This executor never touches a filesystem. It has no `open`, no `os`, no
`pathlib`, no `glob` — the module imports nothing that could reach the host,
which the `test_no_forbidden_capabilities` architecture test enforces across
the whole package.

Its three branches are exactly the fixtures the contract mandates. It is a
drop-in shape for the real read-only implementation of Phase 5: same
`ToolSpec`, same argument schema, same result schema, so replacing it is a
registry wiring change rather than a controller change.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ..contracts import FileSearchArgs, FileSearchResult
from ..registry import SideEffect, ToolExecutor, ToolSpec, admit


class FakeFileSearchExecutor:
    """In-memory fixture executor.

    `calls` records the arguments of every invocation. The adversarial tests
    use it as the spy that proves a rejected proposal never reached
    execution: for every rejection case the assertion is not merely "the
    right error came back" but also "this list is still empty".
    """

    def __init__(self) -> None:
        self.calls: list[FileSearchArgs] = []

    def execute(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, FileSearchArgs)  # controller validated it first
        self.calls.append(args)

        if args.query == "Jeep clutch notes":
            return {
                "status": "success",
                "data": ["clutch_replacement.md"],
            }
        if args.query == "timeout_trigger":
            raise TimeoutError("Simulated execution timeout")
        return {
            "status": "success",
            "data": [],
        }

    @property
    def call_count(self) -> int:
        return len(self.calls)


def build_file_search_spec(executor: ToolExecutor | None = None) -> ToolSpec:
    """The controller-owned definition of the `file_search` capability.

    Returned already admitted: `admit` is the only way into a registry, and
    running it here means a capability is checked at the moment it is defined
    rather than at the moment someone remembers to.
    """
    return admit(
        ToolSpec(
            name="file_search",
            args_schema=FileSearchArgs,
            executor=executor or FakeFileSearchExecutor(),
            timeout_seconds=5.0,
            requires_authorization=True,
            destructive=False,
            result_schema=FileSearchResult,
            # A search observes; it changes nothing. Both derived properties
            # follow: nothing happened, and repeating is free.
            side_effect=SideEffect.NONE,
        )
    )
