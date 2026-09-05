# Milestone 2 — Decisions, Conflicts, and Limitations

Milestone 2 adds the first real external capability: read-only filesystem
access. This records the judgement calls, the two specification conflicts
found and how they were resolved, and — importantly — what this capability
does *not* protect against.

## 1. Conflict: ten failure categories, eight error codes

**The conflict.** The milestone asks (§12) for at least ten distinguishable
filesystem failure categories, while also requiring (§11) that the existing
`ControllerError` be reused and no second error protocol invented. But
`ControllerError.code` is a closed `Literal` of exactly eight codes, fixed by
the Milestone 1 contract (spec 03 §4, 07 §4).

**Resolution.** The distinction is made on two channels, which is what the
existing design already does for the authorization and policy gates:

* **Externally** — the model sees one of the eight existing codes.
* **Internally** — the audit stream records a stable reason slug
  (`fs_path_escapes_root`, `fs_broken_symlink`, …), exactly as
  `policy.Decision.reason` already did.

No code was added to the `Literal`, and no parallel protocol exists. §11
explicitly anticipates this: "Internal audit data may record a stable
internal reason code."

## 2. Conflict: non-retryable denials from inside the executor

**The conflict.** §12 requires that a path escaping its root must not become
a retry loop. But path containment can only be determined *after* physical
resolution, which is the executor's job — and every failure an executor could
previously report (`ToolExecutionError`) maps to `EXECUTION_FAILED`, which
Milestone 1 defines as retryable.

**Resolution.** A second executor signal, `ToolDenialError`, which the
controller normalizes to `POLICY_DENIED` — the same non-retryable code, the
same opaque message, as the `AUTHORIZE` and `POLICY_CHECK` gates. The model
cannot tell which of the three said no.

This is a safe direction to admit. An executor can only *deny*: it has no way
to grant authority it was not wired with, so the new path is fail-closed. It
does not weaken the Milestone 1 rule that both gates emit `POLICY_DENIED`; it
adds a third source of the same verdict.

The controller still performs no filesystem access. It catches a typed
exception from a module it already depends on.

## 3. Conflict: "the registry must contain exactly the two tools"

§13 requires the registry to hold exactly `workspace.list` and
`workspace.read`. Milestone 1's registry holds exactly `file_search`, and its
tests assert that.

**Resolution.** Two builders, not one merged registry:
`wiring.build_default_registry()` is the Milestone 1 wiring, and
`wiring.build_filesystem_registry(roots, limits)` is the Milestone 2 wiring.
They cannot be merged in any case — the filesystem registry requires physical
roots that the Milestone 1 builder has no way to supply. Both are tested for
exact contents, and neither contains the other's tools.

## 4. The two-layer path model

Containment is enforced twice, at two layers that fail in different ways.

**Layer 1 — syntactic, in the schema, before any filesystem contact.**
`contracts._canonical_relative_path` refuses absolute paths, `~`, backslashes,
drive letters, UNC prefixes, NUL bytes, every `..` segment, and the
non-canonical `.`, `//`, and trailing-separator forms. Result:
`SCHEMA_INVALID`, and nothing has touched a disk.

This layer is load-bearing rather than cosmetic, because of a pathlib
behaviour that is easy to miss:

```python
Path("/srv/workspace") / "/etc/passwd"  # -> Path("/etc/passwd")
```

An absolute path silently *replaces* the root when joined. Refusing it before
the join is the fix; there is a test asserting this join behaviour so the
reason for the check cannot be forgotten.

**Layer 2 — physical, in the executor, after resolution.**

```python
authorized_root = configured_root.resolve(strict=True)  # once, at wiring
candidate = (authorized_root / relative).resolve(strict=True)
if not candidate.is_relative_to(authorized_root):
    deny()
```

Neither layer is sufficient alone: the first cannot see symlinks, and the
second cannot run before a path has been joined.

**Why `is_relative_to` and never `startswith`.** `is_relative_to` compares
path components. A string prefix test does not:

```python
str("/srv/workspace_evil/loot.txt").startswith("/srv/workspace")  # True
Path("/srv/workspace_evil/loot.txt").is_relative_to("/srv/workspace")  # False
```

`test_sibling_prefix_directory_is_not_inside_the_root` asserts *both* halves —
that the naive check would have been fooled, and that the real one is not — so
a regression to `startswith` fails a test whose name says why it exists.

**Why the root is resolved at wiring time.** The comparison is only sound
between two fully resolved paths. If the configured root were itself reached
through a symlink (`/tmp` → `/private/tmp` on macOS), every legitimate child
would appear to escape it.

## 5. Symlink policy: resolve first, then authorize the target

Symlinks are not banned. The policy is the one the contract specifies:
resolve fully, then authorize the physical target.

| Case | Outcome |
|---|---|
| link → file inside the root | followed, allowed |
| link → directory inside the root | followed, allowed |
| link chain staying inside | followed, allowed |
| link → file outside the root | `POLICY_DENIED`, no read |
| link → directory outside the root | `POLICY_DENIED`, no read |
| link → a sibling-prefix directory | `POLICY_DENIED`, no read |
| link → the *other* authorized root | `POLICY_DENIED` — `root_id` selects the root, the path cannot re-select it |
| broken link | `EXECUTION_FAILED` / `fs_broken_symlink` |
| symlink loop | `EXECUTION_FAILED` / `fs_resolution_failed` |

Directory *listings* never follow a link at all: `_classify` tests
`is_symlink()` first and short-circuits, so an entry pointing outside the root
is labelled `symlink` without its target being stat'ed. A listing therefore
discloses nothing about what is outside — not even whether it exists.

**A version-specific trap.** On CPython 3.11 a symlink loop raises
`RuntimeError("Symlink loop from '<physical path>'")`, not `OSError` — so an
`except OSError` chain lets it escape *with the host path in the message*.
CPython 3.13+ raises `OSError(ELOOP)` instead. The executor catches both, and
a test asserts the fixture's absolute path does not appear in the model-facing
error.

## 6. Rejection, not truncation

Every ceiling is enforced by rejecting the request, never by silently
returning a shortened result. A truncated file or listing is indistinguishable
from a complete one to whatever reads it next, which is a poor property for
data a model will reason over.

## 7. Bytes are bytes

`max_file_read_bytes` is enforced on bytes, not characters — ten 3-byte
characters are 30 bytes, and a character-based limit would bound neither
memory nor transfer. The read is bounded at the source:

```python
raw = handle.read(ceiling + 1)  # enough to detect oversize, never to load it
if len(raw) > ceiling:
    deny()
```

Peak memory is `ceiling + 1` bytes regardless of the file's real size. An
oversized file is never fully read, and decoding happens only after the size
is known to be acceptable — so a whole-file read below the ceiling can never
split a multi-byte character.

## 8. Deterministic listing order

Entries are sorted by `name` using Python's default string comparison, which
is Unicode code-point order: locale-independent, platform-independent, and
unrelated to the order the OS yields entries in. Uppercase therefore sorts
before lowercase (`Apple.txt` before `middle.txt`), which the test asserts
explicitly so the rule is pinned rather than assumed.

## 9. Result shape

`DirectoryEntry.kind` is one of `file`, `directory`, `symlink`, `other` — the
milestone's conceptual example shows only the first two, and `symlink` is
added because reporting a link as a plain file or directory would require
following it. `other` covers sockets, FIFOs, and device nodes.

No absolute path, inode, device, owner, permission bits, or timestamp appears
in any result. The only path a result carries is the model's own abstract one.

## 10. An empty path means the root

`workspace.list` accepts `path: ""` to mean the root directory itself, rather
than accepting `"."`. The validator refuses `.` segments so that one file is
reachable by exactly one string; `""` gives an unambiguous way to name the root
without reintroducing that ambiguity. `workspace.read` requires a non-empty
path via its own `min_length=1`.

## 11. Wiring does not import `pathlib`

`build_physical_roots` names root locations using a `RootLocation` alias
exported by the executor module, so `wiring.py` needs no filesystem import of
its own. The filesystem grant is held by exactly one production module, and
`test_only_the_filesystem_executor_holds_a_filesystem_grant` asserts that the
list of modules importing any filesystem module is exactly
`["workspace_fs.py"]`.

## 12. Known limitations — read this part

**This is not an OS-level sandbox.** Path containment protects the capability
boundary *within the configured roots*. It does not protect against every
operating-system or filesystem attack, and it is not a substitute for process
isolation. Nothing here uses namespaces, chroot, seccomp, or a jail, and
§24 of the milestone contract deliberately defers all of that.

Specifically, the following are **not** defended against:

* **Time-of-check to time-of-use (TOCTOU).** A path is resolved and
  authorized, then opened. An attacker who can *write* to the authorized root
  could swap a file for a symlink in that window. Closing this requires
  `openat`/`O_NOFOLLOW`, which needs `os` and would widen the capability grant
  beyond what this milestone opened.
* **Hard links.** A hard link inside a root that refers to data outside it is
  indistinguishable from an ordinary file by path resolution, because there is
  no link to follow. Detecting it needs device/inode comparison against every
  authorized root.
* **Anything requiring write access to a root.** Both items above assume an
  attacker who can already create files inside an authorized root. The model
  cannot — this capability is read-only, and nothing in Milestone 2 grants
  write access to anything.
* **Case-insensitive filesystems.** On macOS and Windows, `README.md` and
  `readme.md` may name the same file. This is not an escape (the target is
  still inside the root) but it means path identity is platform-dependent.
* **Physical roots pointing somewhere unwise.** Trusted wiring chooses them.
  Binding `workspace` to `/` would be a deployment error this code cannot
  detect, and the model still could not escape the root it was given — it
  would simply have been given too much.

**One test does not run as root.** `test_permission_failures_are_normalized`
skips when `geteuid() == 0`, because permission bits do not restrain root. It
executes in CI, which runs as an unprivileged user, and skips honestly in a
root container rather than passing vacuously.

## 13. Resource ceilings

| Ceiling | Default | Authority |
|---|---|---|
| `max_file_read_bytes` | 262,144 (256 KiB) | `policy.FilesystemLimits` |
| `max_directory_entries` | 1,000 | `policy.FilesystemLimits` |
| `max_path_length` | 1,024 | `policy.FilesystemLimits` (may tighten the schema's `MAX_PATH_LENGTH`) |
| `max_serialized_result_bytes` | 524,288 (512 KiB) | `policy.FilesystemLimits` |

No argument schema exposes any of these. The model chooses *what* to read,
never *how much*. Trusted wiring hands the same frozen `FilesystemLimits`
object to both `RunContext` and the executors, so the ceiling policy declares
is the ceiling the executor enforces — one source of truth rather than two
that can drift.

## 14. Error classification and retry disposition

| Category | External code | Retryable | Internal reason |
|---|---|---|---|
| invalid schema / bad path syntax | `SCHEMA_INVALID` | yes | pydantic field errors |
| path escapes root | `POLICY_DENIED` | **no** | `fs_path_escapes_root` |
| unauthorized root or tool | `POLICY_DENIED` | **no** | `root_not_granted`, `tool_not_granted` |
| root not wired | `POLICY_DENIED` | **no** | `fs_root_not_configured` |
| unsupported object (FIFO, socket, device) | `POLICY_DENIED` | **no** | `fs_unsupported_object` |
| byte ceiling exceeded | `POLICY_DENIED` | **no** | `fs_read_exceeds_byte_ceiling` |
| entry ceiling exceeded | `POLICY_DENIED` | **no** | `fs_entries_exceed_ceiling` |
| result size ceiling exceeded | `POLICY_DENIED` | **no** | `fs_result_exceeds_size_ceiling` |
| undecodable entry name | `POLICY_DENIED` | **no** | `fs_entry_name_not_encodable` |
| path longer than policy allows | `POLICY_DENIED` | **no** | `path_above_policy_length_ceiling` |
| missing file | `EXECUTION_FAILED` | yes (bounded) | `fs_not_found` |
| broken symlink | `EXECUTION_FAILED` | yes (bounded) | `fs_broken_symlink` |
| symlink loop / resolution failure | `EXECUTION_FAILED` | yes (bounded) | `fs_resolution_failed` |
| directory requested as file | `EXECUTION_FAILED` | yes (bounded) | `fs_not_a_regular_file` |
| file requested as directory | `EXECUTION_FAILED` | yes (bounded) | `fs_not_a_directory` |
| permission denied | `EXECUTION_FAILED` | yes (bounded) | `fs_permission_denied` |
| non-UTF-8 content | `EXECUTION_FAILED` | yes (bounded) | `fs_not_utf8` |
| read failure | `EXECUTION_FAILED` | yes (bounded) | `fs_read_failed` |

The split follows one rule: a failure that is a property of the *request*
(escape, ceiling, unsupported type) is a denial and is not retried, because
asking again identically produces the same answer. A failure that is a
property of the *world* (missing, wrong type, permission, encoding) is
retryable and bounded by the existing three-attempt budget, because the model
can legitimately correct its next proposal.
