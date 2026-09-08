"""The constrained artifact writer — the first real side effect (Milestone 8).

One capability, one operation: put exactly these bytes at exactly this abstract
location beneath one authorized root. It exists to prove that the machinery
built by Milestones 1–7 governs a genuine, irreversible physical effect, not to
become a filesystem API.

**Why this is a separate module from `workspace_fs.py`.** That module is
provably read-only: its AST is asserted to call no mutating method and to open
files only in mode `"rb"`, and three Milestone 2 tests depend on it. Putting a
writer beside the readers would have meant weakening those assertions, so the
capability that mutates lives here, holds its own import grant, and carries its
own boundary tests. `workspace_fs.py` remains exactly as read-only as it was.

**Containment is reused, not reimplemented.** `PhysicalRoots` and
`_resolve_within_root` come from the read capability unchanged. There is
exactly one containment implementation in this package, and a traversal bug
would have exactly one place to live.

That reuse needs one adaptation, and it is the interesting part of this module.
`_resolve_within_root` resolves with `strict=True`, so it cannot resolve a
destination that does not exist yet — measured, not assumed. The writer
therefore resolves the *parent directory* through it, which:

* proves the parent is inside the root using the same component-wise check;
* refuses a missing parent, which is how "never create directories" is
  enforced — there is no `mkdir` here to forget to guard;
* leaves exactly one unresolved component, the filename, which by the schema's
  grammar contains no separator, no `..`, and no NUL.

A consequence worth noting: this module never imports `pathlib` at all. It
receives already-resolved `Path` objects from the shared helper and never
constructs one, so it holds strictly less filesystem surface than the reader.

**The leaf is opened with `O_NOFOLLOW`, and that is the security property.**
A pre-flight "is it a symlink?" check is inherently racy: an attacker who wins
the window between the check and the open would have the write follow their
link. `O_NOFOLLOW` moves the check into the same syscall as the open, so the
kernel refuses (`ELOOP`) rather than this code hoping. Measured: a plain
`write_text` through a symlink *does* land outside the root; the same write
with `O_NOFOLLOW` fails and the outside file is untouched.

That covers containment. The explicit type checks before the open are a
different question, and mutation testing separated them: removing the symlink
or directory check changes only the refusal slug, because `O_NOFOLLOW` and
`EISDIR` still hold. Removing the *non-regular* check does not degrade to a
worse error — it blocks forever. Measured: with the check removed, a write to a
FIFO inside the root parks in the kernel's `fifo_open` → `wait_for_partner`
indefinitely, because a FIFO opened for writing without `O_NONBLOCK` waits for
a reader that never arrives, and `O_NOFOLLOW` has nothing to say about it.

`ToolSpec.timeout_seconds` does not rescue that: it is declared, admitted and
recorded, but nothing enforces it with a clock — deliberately, since a
wall-clock interrupt is exactly the non-determinism the suite forbids. So the
FIFO check is the only thing standing between a model-proposed path and an
unbounded hang of the controller. It defends liveness rather than containment,
which is why it is tested by ordering (`os.open` is never reached) rather than
only by outcome: a missing check makes that test fail in milliseconds instead
of hanging the suite.

**What this does not claim.** Not atomic: `O_TRUNC` empties the file at open,
so a crash between the truncate and the final write leaves a shorter file than
either the old or the new content. Not transactional. Not exactly-once. What it
does claim is bounded and tested: the bytes are `fsync`ed before the call
returns, nothing is ever written outside the authorized root, and re-running
the identical request converges on the identical content.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel

from ..contracts import WorkspaceWriteArgs, WorkspaceWriteResult
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

# Opened with the destination's final component never followed. `O_TRUNC`
# replaces content wholesale — this capability has no append or patch mode, so
# there is no partial-update semantics to reason about.
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW

# The mode a *newly created* file is given. An existing file keeps whatever
# mode it already had — `O_CREAT`'s mode argument is ignored when the file
# exists — so this capability never changes a permission, it only chooses one
# for a file that did not exist. Owner read/write is the conservative choice.
_NEW_FILE_MODE = 0o600


class WorkspaceWriteExecutor:
    """`workspace.write` — replace one regular file beneath one authorized root.

    `calls` is the spy the adversarial tests use to prove a rejected proposal
    never reached execution, matching the convention every executor follows.
    `writes` is a second spy specific to this capability, recording only the
    requests that reached the physical `os.open`. The distinction is the whole
    point of a side-effecting capability's tests: "the executor was dispatched"
    and "bytes were written" are different facts, and only the second one is
    irreversible.
    """

    def __init__(
        self,
        roots: PhysicalRoots,
        limits: FilesystemLimits = DEFAULT_FILESYSTEM_LIMITS,
    ) -> None:
        self._roots = roots
        self._limits = limits
        self.calls: list[WorkspaceWriteArgs] = []
        self.writes: list[WorkspaceWriteArgs] = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def write_count(self) -> int:
        """Physical writes performed. The number that matters after a crash."""
        return len(self.writes)

    def execute(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, WorkspaceWriteArgs)  # controller validated it first
        self.calls.append(args)

        # SIZE FIRST, before anything touches a filesystem. The ceiling is on
        # encoded bytes because that is what lands on disk and what a durable
        # record carries; a character count would not bound either.
        payload = args.content.encode("utf-8")
        if len(payload) > self._limits.max_file_write_bytes:
            # Refused, never truncated. A silently shortened artifact is
            # indistinguishable from a complete one to whoever reads it next —
            # the same reasoning the read ceiling uses.
            raise ToolDenialError("fs_write_exceeds_byte_ceiling")

        root = self._roots.resolved(args.root_id)
        parent_path, leaf = _split_destination(args.path)

        # The parent must already exist. Resolving it strictly is what enforces
        # "never create directories": there is no mkdir in this module, so a
        # missing parent can only ever be a refusal.
        parent = _resolve_within_root(root, parent_path)
        if not parent.is_dir():
            raise ToolExecutionError(reason="fs_parent_not_a_directory")

        target = parent / leaf
        # `parent` is resolved and inside `root`, and `leaf` is a single
        # separator-free component, so this holds by construction. Asserted
        # anyway: the property is load-bearing and a future edit to the schema
        # grammar should fail here rather than silently widen the reach.
        if not target.is_relative_to(root):
            raise ToolDenialError("fs_path_escapes_root")

        created = not target.exists() and not target.is_symlink()
        if target.is_symlink():
            # Refused outright rather than resolved. The read capability
            # deliberately follows links that stay inside the root; a writer
            # does not, because "the link still points inside" is a fact with a
            # lifetime shorter than the write. `O_NOFOLLOW` enforces this
            # regardless of what happens after the check.
            raise ToolDenialError("fs_write_target_is_symlink")
        if target.is_dir():
            raise ToolExecutionError(reason="fs_write_target_is_a_directory")
        if target.exists() and not target.is_file():
            # FIFO, socket, device node. Unlike the two checks above, this one
            # has no second mechanism behind it: `os.open` on a FIFO without
            # O_NONBLOCK blocks until a reader appears, and no timeout is
            # enforced anywhere, so removing this line hangs the controller
            # rather than producing a worse error. Measured, not assumed — see
            # the module docstring and `..._refused_before_any_open`.
            raise ToolDenialError("fs_unsupported_object")

        try:
            descriptor = os.open(target, _WRITE_FLAGS, _NEW_FILE_MODE)
        except FileNotFoundError as exc:
            raise ToolExecutionError(reason="fs_not_found") from exc
        except PermissionError as exc:
            raise ToolExecutionError(reason="fs_permission_denied") from exc
        except IsADirectoryError as exc:
            raise ToolExecutionError(reason="fs_write_target_is_a_directory") from exc
        except OSError as exc:
            # ELOOP lands here when the final component became a symlink after
            # the check above — the race the flag exists to lose safely. Also
            # ENXIO for a FIFO with no reader, ENOSPC, EROFS. None of these
            # messages is forwarded: they carry the physical path.
            raise ToolExecutionError(reason="fs_write_refused") from exc

        # From here a physical effect is possible, so the spy records it before
        # the bytes go out. A test asking "did anything happen" must get "yes"
        # even for a write that then failed halfway.
        self.writes.append(args)
        try:
            os.write(descriptor, payload)
            # Durable before the call returns, so the controller's completion
            # record cannot claim more than the filesystem has accepted. This
            # does not fsync the containing directory, so a crash immediately
            # after *creating* a new file could still lose the directory entry
            # — the same bounded claim `persistence/journal.py` makes.
            os.fsync(descriptor)
        except OSError as exc:
            raise ToolExecutionError(reason="fs_write_failed") from exc
        finally:
            os.close(descriptor)

        result = WorkspaceWriteResult(
            status="success",
            root_id=args.root_id,
            path=args.path,
            bytes_written=len(payload),
            created=created,
        )
        if len(result.model_dump_json().encode("utf-8")) > self._limits.max_serialized_result_bytes:
            raise ToolDenialError("fs_result_exceeds_size_ceiling")
        return result.model_dump()


def build_workspace_write_spec(executor: ToolExecutor) -> ToolSpec:
    """Controller-owned definition of `workspace.write`, already admitted.

    **`IDEMPOTENT`, under a bounded definition stated in full in
    `docs/milestone-8-decisions.md` §5.** The bound is the destination
    artifact's existence and content: running the identical request N times
    leaves the same file with the same bytes as running it once, and nothing
    accumulates. Filesystem *metadata* is explicitly outside that bound —
    `mtime` advances on every write and does not converge, measured rather than
    assumed, and a test asserts the non-convergence so the limitation stays
    visible.

    Not `NONE`: something observable happened, so an ambiguous crash is not
    "nothing occurred". Not `MUTATING`: nothing compounds, so refusing to ever
    re-run it would be a restriction the semantics do not earn.

    `destructive` is False. It replaces one named file whose location the run
    holds a grant for; it deletes nothing, renames nothing, and reaches nothing
    it was not pointed at. Admission would reject `destructive=True` here
    anyway, since a destructive capability must be `MUTATING`.
    """
    return admit(
        ToolSpec(
            name="workspace.write",
            args_schema=WorkspaceWriteArgs,
            executor=executor,
            timeout_seconds=5.0,
            requires_authorization=True,
            destructive=False,
            result_schema=WorkspaceWriteResult,
            side_effect=SideEffect.IDEMPOTENT,
        )
    )
