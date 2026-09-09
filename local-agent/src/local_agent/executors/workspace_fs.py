"""Read-only filesystem executors (Milestone 2).

This is the only production module in the package permitted to import
`pathlib` or touch a filesystem, and `tests/test_architecture.py` enforces
that: the controller, policy, state machine, contracts, registry, and wiring
all still fail the build if they acquire a filesystem import. Physical
capability is deliberately concentrated in one auditable file.

What the model can express is an abstract request:

    {"tool": "workspace.read",
     "arguments": {"root_id": "workspace", "path": "src/app.py"}}

`root_id` is a label, not a location. The physical directory it maps to is
chosen by trusted wiring, held in `PhysicalRoots`, and never appears in a
result, an error, or an audit event.

**The containment rule.** A path is authorized only when, after full symlink
resolution, it is still inside the resolved authorized root:

    resolved_candidate.is_relative_to(resolved_authorized_root)

`is_relative_to` compares path *components*, which is why this code does not
use a string prefix test. `str("/srv/workspace_evil/x").startswith("/srv/workspace")`
is `True` — a sibling directory whose name merely begins with the root's name
would pass a prefix check and fail this one. There is a test named for that
attack precisely so the check cannot regress to `startswith`.

**Symlink policy.** Resolve first, then authorize the physical target. A link
inside the root that points back inside the root is fine and is followed; a
link that lands outside is denied, and the denial happens before any read.
The policy is deliberately not "reject all symlinks" — that would break
legitimate layouts, and it would still be the resolution step doing the real
work.

**Read-only by construction.** Nothing here calls `write_text`, `write_bytes`,
`unlink`, `rmdir`, `mkdir`, `rename`, `replace`, `chmod`, `chown`, `touch`,
`symlink_to`, or `hardlink_to`, and the only `open` is mode `"rb"`. There is
no generic `operation(name, path)` seam through which a mutating call could
later be smuggled: adding one would mean adding a class, a schema, a registry
entry, and a test.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeAlias

from pydantic import BaseModel

from ..contracts import (
    DirectoryEntry,
    WorkspaceListArgs,
    WorkspaceListResult,
    WorkspaceReadArgs,
    WorkspaceReadResult,
)
from ..policy import DEFAULT_FILESYSTEM_LIMITS, LEGAL_ROOT_IDS, FilesystemLimits
from ..registry import (
    SideEffect,
    ToolDenialError,
    ToolExecutionError,
    ToolExecutor,
    ToolSpec,
    admit,
)

# Exported so trusted wiring can name a physical root without importing
# `pathlib` itself. The filesystem grant stays confined to this module.
RootLocation: TypeAlias = Path | str


class PhysicalRoots:
    """Trusted mapping from abstract root id to resolved physical directory.

    Built once by wiring from operator configuration. Each root is resolved
    at construction — not per request — because the containment comparison is
    only sound between two fully resolved paths: if the configured root were
    itself reached through a symlink, every legitimate child would appear to
    escape it.

    Construction fails loudly on a missing or non-directory root. That is a
    deployment error, and a controller that silently served a half-configured
    namespace would be worse than one that refuses to start.
    """

    def __init__(self, mapping: Mapping[str, RootLocation]) -> None:
        resolved: dict[str, Path] = {}
        for root_id, location in mapping.items():
            if root_id not in LEGAL_ROOT_IDS:
                raise ValueError(f"unknown abstract root id: {root_id!r}")
            path = Path(location).resolve(strict=True)
            if not path.is_dir():
                raise ValueError(f"physical root for {root_id!r} is not a directory")
            resolved[root_id] = path
        self._roots = resolved

    def resolved(self, root_id: str) -> Path:
        """The physical root for an abstract id, or a denial if none is wired.

        A root the operator did not configure is not an error the model can
        fix, and it must not be distinguishable from any other denial.
        """
        root = self._roots.get(root_id)
        if root is None:
            raise ToolDenialError("fs_root_not_configured")
        return root

    @property
    def root_ids(self) -> frozenset[str]:
        return frozenset(self._roots)


# Path *grammar*, kept beside path *containment* deliberately. Milestone 8 put
# this in the writer; Milestone 9 needed it too, and importing one executor
# from another would have made the append capability depend on the replace
# capability for no reason. Splitting a validated relative path is neither a
# read nor a write — it touches no filesystem — so it lives with the module
# that owns what a path means, and both writers depend only on that.
def _split_destination(path: str) -> tuple[str, str]:
    """Separate the parent directory from the filename.

    Safe because of what the schema already guarantees: `path` is canonical,
    relative, has no empty segment, no `.`, no `..`, no backslash, no NUL, and
    no trailing separator. So the last segment is a plain filename and
    everything before it is a relative directory path — possibly empty, which
    denotes the root itself.
    """
    parent, separator, leaf = path.rpartition("/")
    return (parent if separator else ""), leaf


def _resolve_within_root(root: Path, relative: str) -> Path:
    """Resolve a model-supplied relative path and prove it stays inside `root`.

    Every native failure is translated here, so no `OSError` — whose message
    would carry a physical path — ever escapes toward the model.
    """
    candidate = root / relative if relative else root

    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        # `is_symlink` uses lstat, so it identifies a dangling link without
        # following it. It returns False when the parent itself is missing,
        # which correctly falls through to "not found".
        if candidate.is_symlink():
            raise ToolExecutionError(reason="fs_broken_symlink") from exc
        raise ToolExecutionError(reason="fs_not_found") from exc
    except PermissionError as exc:
        raise ToolExecutionError(reason="fs_permission_denied") from exc
    except NotADirectoryError as exc:
        raise ToolExecutionError(reason="fs_not_a_directory") from exc
    except (OSError, RuntimeError) as exc:
        # Over-long names (ENAMETOOLONG), and symlink loops — which are not
        # uniformly typed across versions: CPython 3.11 raises RuntimeError
        # ("Symlink loop from '<physical path>'") while 3.13+ raises
        # OSError(ELOOP). Both are caught, and neither message is forwarded:
        # the 3.11 one embeds the host path this milestone must never leak.
        raise ToolExecutionError(reason="fs_resolution_failed") from exc

    # THE containment check. Component-wise, never a string prefix.
    if not resolved.is_relative_to(root):
        raise ToolDenialError("fs_path_escapes_root")

    return resolved


def _classify(entry: Path) -> str:
    """Describe a directory entry without following it.

    `is_symlink` is tested first and short-circuits, so a link is never
    dereferenced to label it. A link pointing outside the root therefore
    discloses nothing about what is out there — not even whether it exists.
    """
    if entry.is_symlink():
        return "symlink"
    if entry.is_dir():
        return "directory"
    if entry.is_file():
        return "file"
    return "other"


def _bounded_result(result: BaseModel, limits: FilesystemLimits) -> dict[str, Any]:
    """Final backstop: refuse a result whose serialized size exceeds policy."""
    if len(result.model_dump_json().encode("utf-8")) > limits.max_serialized_result_bytes:
        raise ToolDenialError("fs_result_exceeds_size_ceiling")
    return result.model_dump()


class WorkspaceReadExecutor:
    """`workspace.read` — bounded UTF-8 text from one authorized regular file.

    `calls` is the spy the adversarial tests use to prove a rejected proposal
    never reached execution, matching the Milestone 1 convention.
    """

    def __init__(
        self,
        roots: PhysicalRoots,
        limits: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS,
    ) -> None:
        self._roots = roots
        self._limits = limits
        self.calls: list[WorkspaceReadArgs] = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def execute(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, WorkspaceReadArgs)  # controller validated it first
        self.calls.append(args)

        root = self._roots.resolved(args.root_id)
        target = _resolve_within_root(root, args.path)

        # Type checks happen before any open. That ordering matters beyond
        # tidiness: opening a FIFO for reading blocks until a writer appears,
        # so discovering the type afterwards could hang the controller.
        if target.is_dir():
            raise ToolExecutionError(reason="fs_not_a_regular_file")
        if not target.is_file():
            # Socket, FIFO, device node, or anything else that is neither a
            # regular file nor a directory. This capability does not serve it.
            raise ToolDenialError("fs_unsupported_object")

        ceiling = self._limits.max_file_read_bytes
        try:
            with target.open("rb") as handle:
                # Read at most ceiling+1 bytes: enough to *detect* an oversized
                # file, never enough to load one. Peak memory stays bounded
                # whatever the file's real size is.
                raw = handle.read(ceiling + 1)
        except PermissionError as exc:
            raise ToolExecutionError(reason="fs_permission_denied") from exc
        except OSError as exc:
            raise ToolExecutionError(reason="fs_read_failed") from exc

        if len(raw) > ceiling:
            # Rejected, not truncated: a silently shortened file is
            # indistinguishable from a complete one to whoever reads it next.
            raise ToolDenialError("fs_read_exceeds_byte_ceiling")

        try:
            # The ceiling is in bytes, and it is enforced on bytes. Decoding
            # happens only after the size is known to be acceptable, and a
            # whole file smaller than the ceiling can never split a character.
            content = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ToolExecutionError(reason="fs_not_utf8") from exc

        return _bounded_result(
            WorkspaceReadResult(
                status="success",
                root_id=args.root_id,
                path=args.path,
                content=content,
                bytes_read=len(raw),
            ),
            self._limits,
        )


class WorkspaceListExecutor:
    """`workspace.list` — a deterministic, non-recursive listing of one directory.

    Ordering is by entry name using Python's default string comparison, which
    is Unicode code-point order: locale-independent, platform-independent, and
    unrelated to the order the OS happens to yield entries in.
    """

    def __init__(
        self,
        roots: PhysicalRoots,
        limits: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS,
    ) -> None:
        self._roots = roots
        self._limits = limits
        self.calls: list[WorkspaceListArgs] = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def execute(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, WorkspaceListArgs)  # controller validated it first
        self.calls.append(args)

        root = self._roots.resolved(args.root_id)
        target = _resolve_within_root(root, args.path)

        if target.is_file():
            raise ToolExecutionError(reason="fs_not_a_directory")
        if not target.is_dir():
            raise ToolDenialError("fs_unsupported_object")

        ceiling = self._limits.max_directory_entries
        entries: list[DirectoryEntry] = []
        try:
            for child in target.iterdir():
                name = child.name
                try:
                    # POSIX filenames are bytes, not text: a name that is not
                    # valid UTF-8 reaches Python as surrogate escapes and would
                    # raise deep inside JSON serialization later. Detect it
                    # here, where it can still become a clean denial instead of
                    # an unhandled crash mid-result.
                    name.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise ToolDenialError("fs_entry_name_not_encodable") from exc
                entries.append(DirectoryEntry(name=name, kind=_classify(child)))
                if len(entries) > ceiling:
                    # Bail on the first entry past the ceiling rather than
                    # materializing the whole directory and measuring after.
                    raise ToolDenialError("fs_entries_exceed_ceiling")
        except PermissionError as exc:
            raise ToolExecutionError(reason="fs_permission_denied") from exc
        except OSError as exc:
            raise ToolExecutionError(reason="fs_read_failed") from exc

        entries.sort(key=lambda entry: entry.name)

        return _bounded_result(
            WorkspaceListResult(
                status="success",
                root_id=args.root_id,
                path=args.path,
                entries=entries,
            ),
            self._limits,
        )


def build_workspace_read_spec(executor: ToolExecutor) -> ToolSpec:
    """Controller-owned definition of `workspace.read`, already admitted."""
    return admit(
        ToolSpec(
            name="workspace.read",
            args_schema=WorkspaceReadArgs,
            executor=executor,
            timeout_seconds=5.0,
            requires_authorization=True,
            destructive=False,
            result_schema=WorkspaceReadResult,
            # A read observes; it changes nothing. An ambiguous crash may
            # therefore be resolved by re-executing.
            side_effect=SideEffect.NONE,
        )
    )


def build_workspace_list_spec(executor: ToolExecutor) -> ToolSpec:
    """Controller-owned definition of `workspace.list`, already admitted."""
    return admit(
        ToolSpec(
            name="workspace.list",
            args_schema=WorkspaceListArgs,
            executor=executor,
            timeout_seconds=5.0,
            requires_authorization=True,
            destructive=False,
            result_schema=WorkspaceListResult,
            side_effect=SideEffect.NONE,
        )
    )
