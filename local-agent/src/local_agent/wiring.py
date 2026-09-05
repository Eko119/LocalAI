"""Trusted application wiring.

Everything that grants authority is assembled here, in code, at startup:
which tools exist, which executor backs each one, and what the default run
grants and budget are. Nothing in this module is reachable from model output
— it is the boundary between "what the operator configured" and "what the
model may propose".
"""

from __future__ import annotations

from collections.abc import Mapping

from .executors.file_search import build_file_search_spec
from .executors.workspace_fs import (
    PhysicalRoots,
    RootLocation,
    WorkspaceListExecutor,
    WorkspaceReadExecutor,
    build_workspace_list_spec,
    build_workspace_read_spec,
)
from .policy import DEFAULT_FILESYSTEM_LIMITS, LEGAL_ROOT_IDS, FilesystemLimits, RunContext
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


def build_physical_roots(mapping: Mapping[str, RootLocation]) -> PhysicalRoots:
    """Bind abstract root ids to physical directories chosen by the operator.

    This is the single point at which physical filesystem capability enters
    the system. Nothing downstream can widen it: the model names a root id,
    the executor looks that id up here, and an id with no binding is denied.
    """
    return PhysicalRoots(mapping)


def build_filesystem_registry(
    roots: PhysicalRoots,
    limits: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS,
    read_executor: ToolExecutor | None = None,
    list_executor: ToolExecutor | None = None,
) -> ToolRegistry:
    """The Milestone 2 registry: exactly the two read-only filesystem tools.

    There is no write, delete, rename, move, mkdir, chmod, or shell tool to
    register. As in Milestone 1, the guarantee is structural rather than
    filtered — a mutating request cannot be routed anywhere, because nothing
    in this registry could carry it out.

    The executor overrides exist so tests can substitute a spy while keeping
    the production `ToolSpec`; they are not a runtime configuration surface.
    """
    return ToolRegistry(
        (
            build_workspace_read_spec(read_executor or WorkspaceReadExecutor(roots, limits)),
            build_workspace_list_spec(list_executor or WorkspaceListExecutor(roots, limits)),
        )
    )


def build_filesystem_run_context(
    run_id: str,
    authorized_roots: frozenset[str] = frozenset(LEGAL_ROOT_IDS),
    limits: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS,
    max_attempts: int = 3,
) -> RunContext:
    """A run granted the two filesystem tools and the named abstract roots.

    The same `limits` object should be handed to `build_filesystem_registry`,
    so the ceiling policy declares is the ceiling the executor enforces.
    """
    return RunContext(
        run_id=run_id,
        max_attempts=max_attempts,
        authorized_tools=frozenset({"workspace.read", "workspace.list"}),
        authorized_roots=authorized_roots,
        filesystem=limits,
    )
