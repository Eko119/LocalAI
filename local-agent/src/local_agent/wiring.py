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
from .executors.workspace_append import WorkspaceAppendExecutor, build_workspace_append_spec
from .executors.workspace_fs import (
    PhysicalRoots,
    RootLocation,
    WorkspaceListExecutor,
    WorkspaceReadExecutor,
    build_workspace_list_spec,
    build_workspace_read_spec,
)
from .executors.workspace_write import WorkspaceWriteExecutor, build_workspace_write_spec
from .model_adapter import ModelAdapter
from .model_config import ModelServiceConfig
from .model_service import LocalAIModelAdapter, ToolDescription
from .model_transport import ModelTransport
from .policy import DEFAULT_FILESYSTEM_LIMITS, LEGAL_ROOT_IDS, FilesystemLimits, RunContext
from .registry import ToolExecutor, ToolRegistry
from .transports.http import HttpModelTransport


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


def build_writable_filesystem_registry(
    roots: PhysicalRoots,
    limits: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS,
    read_executor: ToolExecutor | None = None,
    list_executor: ToolExecutor | None = None,
    write_executor: ToolExecutor | None = None,
) -> ToolRegistry:
    """The Milestone 8 registry: the two readers plus the one artifact writer.

    A *separate* builder rather than a flag on `build_filesystem_registry`.
    Every existing caller of that function keeps a registry with no write
    capability in it at all — a deployment cannot acquire the ability to mutate
    a workspace by upgrading, only by deliberately calling this instead. That
    is the same reasoning that makes capabilities named rather than
    parameterised: `include_writer=True` would be one keyword away from being
    set by accident, and one keyword is not enough distance for a side effect.

    There is still no delete, rename, move, mkdir, chmod, or shell capability
    to register. The guarantee remains structural: a mutating request that is
    not "replace this one file" cannot be routed anywhere.
    """
    return ToolRegistry(
        (
            build_workspace_read_spec(read_executor or WorkspaceReadExecutor(roots, limits)),
            build_workspace_list_spec(list_executor or WorkspaceListExecutor(roots, limits)),
            build_workspace_write_spec(write_executor or WorkspaceWriteExecutor(roots, limits)),
        )
    )


def build_mutating_filesystem_registry(
    roots: PhysicalRoots,
    limits: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS,
    read_executor: ToolExecutor | None = None,
    list_executor: ToolExecutor | None = None,
    write_executor: ToolExecutor | None = None,
    append_executor: ToolExecutor | None = None,
) -> ToolRegistry:
    """The Milestone 9 registry: the readers, the writer, and the appender.

    A *third* named builder rather than an `include_mutation=True` flag on the
    writable one, for the reason §8 of the milestone gives and Milestone 8
    established: a keyword is one edit away from being passed by a caller who
    did not consider it, and the gap between "replaces a file" and "cannot be
    repeated at all" is exactly the gap that deserves more distance than a
    default argument.

    So there are now three registries a deployment can ask for, and the
    escalation is monotonic and explicit:

        build_filesystem_registry           read
        build_writable_filesystem_registry  read + replace   (IDEMPOTENT)
        build_mutating_filesystem_registry  read + replace + append (MUTATING)

    Nothing a caller of the first two does can produce the third.
    """
    return ToolRegistry(
        (
            build_workspace_read_spec(read_executor or WorkspaceReadExecutor(roots, limits)),
            build_workspace_list_spec(list_executor or WorkspaceListExecutor(roots, limits)),
            build_workspace_write_spec(write_executor or WorkspaceWriteExecutor(roots, limits)),
            build_workspace_append_spec(append_executor or WorkspaceAppendExecutor(roots, limits)),
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


def build_writable_run_context(
    run_id: str,
    authorized_roots: frozenset[str] = frozenset(LEGAL_ROOT_IDS),
    limits: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS,
    max_attempts: int = 3,
) -> RunContext:
    """A run granted the two readers *and* the artifact writer.

    Separate from `build_filesystem_run_context` for the same reason the
    registry builder is separate: a run that was only ever meant to read must
    not gain a write grant because a default changed. The two grants are
    independent — a run can hold the registry containing the writer and still
    not be authorized to use it, and `authorize` will refuse it.
    """
    return RunContext(
        run_id=run_id,
        max_attempts=max_attempts,
        authorized_tools=frozenset({"workspace.read", "workspace.list", "workspace.write"}),
        authorized_roots=authorized_roots,
        filesystem=limits,
    )


def build_mutating_run_context(
    run_id: str,
    authorized_roots: frozenset[str] = frozenset(LEGAL_ROOT_IDS),
    limits: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS,
    max_attempts: int = 3,
) -> RunContext:
    """A run granted the readers, the writer, and the non-re-executable append.

    Separate from `build_writable_run_context` for the same reason that one is
    separate from the read-only builder. Holding a grant for a capability whose
    failure cannot be retried is a decision a deployment should have to make on
    purpose, and the grant is still independent of the registry: a run can hold
    the mutating registry and not be authorized for `workspace.append`, and
    `authorize` will refuse it.
    """
    return RunContext(
        run_id=run_id,
        max_attempts=max_attempts,
        authorized_tools=frozenset(
            {"workspace.read", "workspace.list", "workspace.write", "workspace.append"}
        ),
        authorized_roots=authorized_roots,
        filesystem=limits,
    )


# What the model is told each tool is for. Kept here, in trusted wiring, rather
# than on `ToolSpec`: these strings are written for the model to read, and
# nothing in the controller consults them.
TOOL_DESCRIPTIONS: dict[str, str] = {
    "workspace.read": "Read UTF-8 text from a file in an authorized root.",
    "workspace.list": "List the entries of a directory in an authorized root.",
    "file_search": "Search for files matching a query in an authorized root.",
    "workspace.write": "Create or replace one file in an authorized root with the given text.",
    "workspace.append": "Add the given text to the end of an existing file in an authorized root.",
}


def describe_tools(registry: ToolRegistry) -> tuple[ToolDescription, ...]:
    """Project the registry onto the deliberately model-visible surface.

    The model learns each tool's name and argument schema — enough to form a
    well-shaped proposal — and nothing else. It does not learn which executor
    backs a tool, which physical directory a root id resolves to, what the
    policy ceilings are, or whether this run is authorized to use the tool at
    all. Authorization is answered later, by the gates, on the proposal itself.

    The `ToolRegistry` object never reaches the adapter; only this frozen
    description does.
    """
    return tuple(
        ToolDescription(
            name=name,
            description=TOOL_DESCRIPTIONS.get(name, ""),
            parameters=spec.args_schema.model_json_schema(),
        )
        for name in sorted(registry.names)
        if (spec := registry.get(name)) is not None
    )


def build_model_adapter(
    config: ModelServiceConfig,
    registry: ToolRegistry,
    transport: ModelTransport | None = None,
) -> ModelAdapter:
    """Assemble the production model adapter.

    `transport` exists so tests can substitute a deterministic in-process
    double while keeping the production adapter byte-for-byte; it is not a
    runtime configuration surface. Left unset, the adapter talks to the
    configured LocalAI service over HTTP.
    """
    return LocalAIModelAdapter(
        transport=transport or HttpModelTransport(config),
        config=config,
        tools=describe_tools(registry),
    )
