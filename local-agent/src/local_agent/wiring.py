"""Trusted application wiring.

Everything that grants authority is assembled here, in code, at startup:
which tools exist, which executor backs each one, and what the default run
grants and budget are. Nothing in this module is reachable from model output
— it is the boundary between "what the operator configured" and "what the
model may propose".
"""

from __future__ import annotations

from .executors.file_search import build_file_search_spec
from .registry import ToolExecutor, ToolRegistry


def build_default_registry(
    file_search_executor: ToolExecutor | None = None,
) -> ToolRegistry:
    """The Milestone 1 registry: exactly one tool, backed by a fake executor.

    There is no shell tool, no write tool, and no network tool to register —
    the reason hostile text like `rm -rf /` cannot execute is not that it is
    filtered, but that nothing in this registry could run it.
    """
    return ToolRegistry((build_file_search_spec(file_search_executor),))
