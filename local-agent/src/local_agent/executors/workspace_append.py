"""The first non-re-executable mutation (Milestone 9).

One capability, one operation: add exactly these bytes to the end of exactly
this existing file beneath one authorized root. It exists to occupy a corner of
the capability contract that nothing had occupied before — *not* side-effect
free and *not* re-executable — and to find out whether the machinery built by
Milestones 1-8 represents that state honestly or merely appears to.

**Why appending, and why it is not the obvious reason.** Non-idempotence is
easy to find; the constraint was to find it without expanding the architecture.
The system holds exactly three physical grants (workspace filesystem, journal,
network), and the journal is controller-owned while network mutation is out of
scope, so an observable effect can only live in the workspace. Within the
workspace, `unlink`, `rename` and `mkdir` are syscalls this package has never
made, and reaching for one would mean widening authority to obtain a semantic
property. Appending needs none of that:

    Milestone 8   O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW
    Milestone 9   O_WRONLY |                     O_NOFOLLOW | O_APPEND

Strictly fewer capabilities, one flag exchanged. That — not the fact that
appending twice differs from appending once — is why this operation was
selected. It is the smallest perturbation of an already-audited primitive that
lands in the fourth corner.

**Dropping `O_CREAT` is load-bearing.** The destination must already exist, so
there is no creation mode, no permission choice, no `created` flag and no
truncation semantics to reason about. A missing file is refused by the kernel
(`ENOENT`) rather than by a check that a later edit could relax. This is what
stops Milestone 9 from turning into a filesystem-semantics milestone: the only
genuinely new thing here is the classification.

**The offset is the kernel's, never this module's.** Under `O_APPEND` the seek
to end-of-file and the write are one operation. A `seek`-then-`write` pair
would be two syscalls with a race between them, which is the same argument that
made `O_NOFOLLOW` preferable to a pre-flight symlink check in Milestone 8. This
module contains no `lseek`, computes no position, and reads no file size.

**Containment is Milestone 2's, unchanged.** `PhysicalRoots` and
`_resolve_within_root` are imported from the read capability exactly as the
writer imports them, so there is still exactly one containment implementation
in this package. The parent is resolved strictly — which is what refuses a
missing directory and what stops a symlinked parent escaping, since
`O_NOFOLLOW` guards only the final component — and the leaf is opened with the
flag.

**What is not claimed.** Not atomic, not transactional, not exactly-once, not
rollback-safe. A short write leaves a partial effect and is reported as one
rather than being completed by a loop, because bytes already in the file cannot
be taken back and appending the remainder later is indistinguishable from
appending them twice. The single guarantee this module supports is the narrow
one Milestone 9 is about: because repeating is unsafe, the controller must
never repeat it automatically. That is enforced by `SideEffect.MUTATING` and
proven by counting physical executions, not by anything written here.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel

from ..contracts import WorkspaceAppendArgs, WorkspaceAppendResult
from ..policy import DEFAULT_FILESYSTEM_LIMITS, FilesystemLimits
from ..registry import (
    SideEffect,
    ToolDenialError,
    ToolExecutionError,
    ToolExecutor,
    ToolSpec,
    admit,
)
from .workspace_fs import PhysicalRoots, _resolve_within_root, _split_destination

# No `O_CREAT`: a missing destination is refused by the kernel, so "never
# creates a file" is a property of the flags rather than of a guard. No
# `O_TRUNC`: this capability only ever adds. `O_APPEND` puts the positioning
# inside the write operation, so no offset is ever computed here.
_APPEND_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW


class WorkspaceAppendExecutor:
    """`workspace.append` — add bytes to one existing file beneath one root.

    Carries the same two spies as the Milestone 8 writer, for the same reason:
    `calls` records dispatch and `appends` records reaching the physical open.
    Only the second is irreversible. For this capability the distinction is
    sharper than it was for the writer, because a repeated dispatch that never
    reached a disk is harmless while a repeated *append* is exactly the hazard
    the classification exists to prevent — so the retry tests count `appends`,
    not `calls`.
    """

    def __init__(
        self,
        roots: PhysicalRoots,
        limits: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS,
    ) -> None:
        self._roots = roots
        self._limits = limits
        self.calls: list[WorkspaceAppendArgs] = []
        self.appends: list[WorkspaceAppendArgs] = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def append_count(self) -> int:
        """Physical appends performed. The number that matters after a crash."""
        return len(self.appends)

    def execute(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, WorkspaceAppendArgs)  # controller validated it first
        self.calls.append(args)

        # SIZE FIRST, before anything touches a filesystem, on encoded bytes
        # because that is what lands on disk and what a durable record carries.
        payload = args.content.encode("utf-8")
        if len(payload) > self._limits.max_file_append_bytes:
            # Refused, never truncated. Silently appending a prefix would put
            # a partial record into a file whose next reader cannot tell it
            # from a complete one — and unlike a truncated write, the partial
            # content would sit at the end of otherwise valid data.
            raise ToolDenialError("fs_append_exceeds_byte_ceiling")

        root = self._roots.resolved(args.root_id)
        parent_path, leaf = _split_destination(args.path)

        # Strict resolution of the parent, exactly as the writer does it. This
        # is what refuses a missing directory, and it is what stops a symlinked
        # *parent* escaping the root — `O_NOFOLLOW` below guards only the final
        # component, measured in Milestone 8 and unchanged here.
        parent = _resolve_within_root(root, parent_path)
        if not parent.is_dir():
            raise ToolExecutionError(reason="fs_parent_not_a_directory")

        target = parent / leaf
        # Holds by construction — `parent` is resolved and inside `root`, and
        # `leaf` is a single separator-free component — and is asserted anyway
        # because the property is load-bearing.
        if not target.is_relative_to(root):
            raise ToolDenialError("fs_path_escapes_root")

        if target.is_symlink():
            # Refused rather than resolved, as in the writer: "the link still
            # points inside" is a fact with a lifetime shorter than the write.
            raise ToolDenialError("fs_append_target_is_symlink")
        if target.is_dir():
            raise ToolExecutionError(reason="fs_append_target_is_a_directory")
        if not target.exists():
            # This capability never creates. The open would fail with ENOENT
            # anyway because there is no `O_CREAT`; the explicit check exists
            # to produce a stable slug instead of a bare errno.
            raise ToolExecutionError(reason="fs_not_found")
        if not target.is_file():
            # FIFO, socket, device node. As in the writer this one is not
            # defence in depth: `os.open` on a FIFO without `O_NONBLOCK` blocks
            # until a reader appears and no timeout is enforced anywhere, so
            # removing this line hangs the controller rather than producing a
            # worse error. It defends liveness, and is tested by ordering.
            raise ToolDenialError("fs_unsupported_object")

        try:
            descriptor = os.open(target, _APPEND_FLAGS)
        except FileNotFoundError as exc:
            raise ToolExecutionError(reason="fs_not_found") from exc
        except PermissionError as exc:
            raise ToolExecutionError(reason="fs_permission_denied") from exc
        except IsADirectoryError as exc:
            raise ToolExecutionError(reason="fs_append_target_is_a_directory") from exc
        except OSError as exc:
            # ELOOP when the leaf became a symlink after the check — the race
            # the flag exists to lose safely. Also ENXIO, ENOSPC, EROFS. None
            # of these messages is forwarded: they carry the physical path.
            raise ToolExecutionError(reason="fs_append_refused") from exc

        # From here a physical effect is possible, so the spy records it before
        # the bytes go out. For a non-re-executable capability this ordering is
        # the difference between "we know something may have happened" and a
        # silent duplicate on the next attempt.
        self.appends.append(args)
        try:
            written = os.write(descriptor, payload)
            os.fsync(descriptor)
        except OSError as exc:
            raise ToolExecutionError(reason="fs_append_failed") from exc
        finally:
            os.close(descriptor)

        if written != len(payload):
            # A short write is a genuine partial effect, and it is deliberately
            # NOT completed by looping. The bytes already in the file cannot be
            # taken back, and appending the remainder afterwards is
            # indistinguishable — to the file and to this code — from appending
            # it twice. Reporting the partial state is the honest outcome; the
            # error is non-retryable for the same reason the capability is.
            raise ToolExecutionError(reason="fs_append_incomplete")

        result = WorkspaceAppendResult(
            status="success",
            root_id=args.root_id,
            path=args.path,
            # What the syscall reported, not what was requested. Reporting the
            # requested count would state something the filesystem never
            # confirmed.
            bytes_appended=written,
        )
        if len(result.model_dump_json().encode("utf-8")) > self._limits.max_serialized_result_bytes:
            raise ToolDenialError("fs_result_exceeds_size_ceiling")
        return result.model_dump()


def build_workspace_append_spec(executor: ToolExecutor) -> ToolSpec:
    """Controller-owned definition of `workspace.append`, already admitted.

    **`MUTATING`, and this is the first capability that means it.** The enum's
    default finally matches a real capability instead of being the conservative
    fallback nothing used.

    Not `NONE`: bytes reach a disk and a later read observes them, so an
    ambiguous crash is emphatically not "nothing happened". Declaring `NONE`
    would make recovery report `execution_pending_repeatable` and offer a
    resume, which is the precise failure Milestone 9 exists to prevent.

    Not `IDEMPOTENT`: measured against Milestone 8's own written bound —
    *idempotent with respect to the destination artifact's existence and
    content* — appending fails it. Applying the identical request to a file
    holding `seed\\n` once yields `seed\\nentry\\n` and twice yields
    `seed\\nentry\\nentry\\n`. The difference is content, which is inside the
    declared effect rather than metadata, so this is the same test Milestone 8
    passed, falling the other way.

    The two derived properties follow and cannot drift, because they are
    computed rather than stored: `side_effect_free` is False (something
    observable happened) and `re_executable` is False (repeating compounds it).
    That pair is the whole milestone — the controller's retry gate and
    recovery's resume gate both read the second one, and neither may substitute
    the first for it.

    `destructive` is False, which is not a loophole. The flag asks whether
    something that existed is removed or overwritten; an append removes nothing
    and overwrites nothing, it only adds. `MUTATING` and `destructive` are
    different axes, which is this milestone's own thesis applied to two more
    fields.
    """
    return admit(
        ToolSpec(
            name="workspace.append",
            args_schema=WorkspaceAppendArgs,
            executor=executor,
            timeout_seconds=5.0,
            requires_authorization=True,
            destructive=False,
            result_schema=WorkspaceAppendResult,
            side_effect=SideEffect.MUTATING,
        )
    )
