#!/usr/bin/env python3
"""PreToolUse guard: refuse edits and commands that break the current milestone scope.

This is a *defence-in-depth* layer, not the primary control. The primary
controls are the typed contracts, the transition table, and
`tests/test_architecture.py`, which fail the build if a forbidden capability
appears. This hook simply catches the mistake earlier, at the moment an
assistant tries to write it.

Contract: reads the PreToolUse payload on stdin; exit 2 blocks the call and
returns stderr to the model; exit 0 allows it.

It fails *open* on unrecognised input — a hook that crashes the session is
worse than a hook that defers to the test suite it duplicates.
"""

from __future__ import annotations

import json
import re
import sys

# Capabilities no module acquires without an explicit per-module grant below.
FORBIDDEN_IMPORTS = re.compile(
    r"^\s*(?:import|from)\s+"
    r"(os|sys|subprocess|shutil|pathlib|glob|tempfile|socket|ssl|http|urllib|"
    r"requests|httpx|aiohttp|sqlite3|docker|playwright|selenium|qdrant_client|"
    r"llama_cpp|transformers|torch|openai|anthropic|mcp|threading|multiprocessing)"
    r"\b",
    re.MULTILINE,
)

FORBIDDEN_COMMANDS = [
    (re.compile(r"\bplaywright\s+install\b"), "Playwright is out of scope until Phase 6."),
    (re.compile(r"\bdocker\s+(run|build|compose)\b"), "Docker execution is out of scope."),
    (re.compile(r"\bqdrant\b"), "Qdrant is out of scope until Phase 8."),
    (
        re.compile(
            r"\b(pip|uv)\s+(pip\s+)?install\b.*\b"
            r"(playwright|selenium|qdrant-client|llama-cpp-python|torch|"
            r"transformers|docker|requests|httpx)\b"
        ),
        "That dependency belongs to a later milestone.",
    ),
    (
        re.compile(r"\b(huggingface-cli|hf)\s+download\b|\bwget\b.*\.gguf|\bcurl\b.*\.gguf"),
        "Model downloads are out of scope.",
    ),
]

# Milestone 6: there is no admin mode, and adding one would undo the milestone.
# Matched in written source rather than in commands, because this is a thing an
# assistant would *implement* under pressure to make a blocked recovery pass.
# Milestone 6: there is no admin mode, and adding one would undo the milestone
# in a single edit. Guarded here because this is the shape an assistant reaches
# for under pressure to make a blocked recovery pass.
#
# Matched on *identifiers in executable position* rather than on text. The
# project's own docstrings legitimately say "turns a denial into a bypass
# tutorial" and "assumed unsafe to repeat", and a text scan flags those — the
# same docstring-versus-code confusion that has bitten three checks in this
# repository already. An identifier followed by `=`, `(` or `:` is code.
BYPASS_WORDS = frozenset(
    {
        "force",
        "unsafe",
        "bypass",
        "superuser",
        "emergency",
        "override",
        "unrestricted",
        "nocheck",
        "noverify",
        "unchecked",
        "admin",
    }
)

# An identifier (optionally after `def`/`class`) sitting where code puts one:
# assigned to, called, or annotated.
# A zero-width lookbehind rather than a consumed character: a consuming
# boundary makes adjacent identifiers invisible, so `recover(force=False)`
# would be missed because the match for `recover(` ate the paren.
IDENTIFIER_IN_CODE = re.compile(
    r"(?<![A-Za-z0-9_])(?:def\s+|class\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=(:]", re.MULTILINE
)

# The command-line spelling, which appears inside string literals rather than
# as an identifier.
BYPASS_FLAG = re.compile(r"--(force|unsafe|ignore-policy|bypass|superuser|emergency)\b")


def _bypass_identifier(text: str) -> str | None:
    """The first identifier in executable position built from a bypass word.

    Split on `_` so `bypass_policy`, `allow_unsafe` and `FORCE_RESUME` are all
    caught, while `enforcement` and `reinforce` are not — those contain
    "force" as a substring but never as a part.
    """
    flag = BYPASS_FLAG.search(text)
    if flag:
        return flag.group(0)
    for match in IDENTIFIER_IN_CODE.finditer(text):
        name = match.group(1)
        parts = {part for part in name.lower().split("_") if part}
        if parts & BYPASS_WORDS:
            return name
    return None


# Only guard the agent subproject's production package.
GUARDED_PATH = re.compile(r"local-agent/src/local_agent/.*\.py$")

# Capability grants are per module, expressed here exactly as they are in
# `MODULE_IMPORT_GRANTS` in tests/test_architecture.py: never by widening the
# global rule. Keep the two in step — the test is the enforcement, this is the
# early warning, and a grant present in only one of them is a drift bug.
#
#   workspace_fs.py  Milestone 2: the only reader of a workspace
#   http.py          Milestone 3: the only network client (`asyncio` rides
#                    along because the stdlib client is blocking)
#   journal.py       Milestone 5: the only writer of durable state (`fcntl`
#                    is the advisory lock that stops two live recoveries)
#   workspace_append.py
#                    Milestone 9: the only non-re-executable mutation. Holds
#                    `os` and one flag fewer than the writer — no O_CREAT, no
#                    O_TRUNC — so "never creates a file" is a property of the
#                    flags. Separate from workspace_write.py because the two
#                    carry different SideEffect classes.
#   workspace_write.py
#                    Milestone 8: the only writer of workspace artifacts. It
#                    holds `os` and not `pathlib` — it receives already-resolved
#                    paths from `workspace_fs` and constructs none, so it has
#                    strictly less filesystem surface than the reader it
#                    borrows containment from. Kept a separate module precisely
#                    so `workspace_fs.py` stays provably read-only.
#
# `persistence/records.py` needs no entry: its `hashlib` and `uuid` imports are
# not capabilities and are not on the forbidden list. The architecture test
# grants them explicitly because it checks a stricter allowlist.
MODULE_GRANTS = {
    "workspace_fs.py": {"pathlib"},
    "http.py": {"urllib"},
    "journal.py": {"os", "pathlib"},
    "workspace_write.py": {"os"},
    "workspace_append.py": {"os"},
    # Milestone 7: `registry.py` content-addresses a capability. Neither
    # `hashlib` nor `types` (for MappingProxyType) performs I/O, opens a
    # socket, or reads ambient state, and neither is on the forbidden list —
    # the entry is here so the two grant tables read the same.
    "registry.py": set(),
}


def _block(reason: str) -> None:
    print(f"Milestone scope guard: {reason}", file=sys.stderr)
    print(
        "See local-agent/.claude/rules/architecture.md. If a later milestone is "
        "genuinely open, update the scope rules and tests first.",
        file=sys.stderr,
    )
    sys.exit(2)


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        tool = payload.get("tool_name", "")
        tool_input = payload.get("tool_input") or {}
    except (json.JSONDecodeError, AttributeError):
        sys.exit(0)  # fail open; the test suite is the real gate

    if tool == "Bash":
        command = str(tool_input.get("command", ""))
        for pattern, reason in FORBIDDEN_COMMANDS:
            if pattern.search(command):
                _block(reason)

    elif tool in {"Write", "Edit", "MultiEdit"}:
        path = str(tool_input.get("file_path", ""))
        if not GUARDED_PATH.search(path):
            sys.exit(0)
        written = " ".join(
            str(tool_input.get(key, "")) for key in ("content", "new_string", "new_str")
        )
        bypass = _bypass_identifier(written)
        if bypass:
            _block(
                f"`{bypass}` looks like a recovery or policy bypass. There is no admin "
                f"mode: if recovery is blocked, the answer is a new run."
            )

        granted = MODULE_GRANTS.get(path.rsplit("/", 1)[-1], set())
        for match in FORBIDDEN_IMPORTS.finditer(written):
            module = match.group(1)
            if module in granted:
                continue
            _block(
                f"`{match.group(0).strip()}` introduces a capability this module "
                f"is not granted (no filesystem, shell, network, or model runtime)."
            )

    sys.exit(0)


if __name__ == "__main__":
    main()
