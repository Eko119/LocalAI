#!/usr/bin/env python3
"""PreToolUse guard: refuse edits and commands that break Milestone 1 scope.

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

# Capabilities Milestone 1 must not acquire (task hard-scope list).
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
        re.compile(r"\b(pip|uv)\s+(pip\s+)?install\b.*\b"
                   r"(playwright|selenium|qdrant-client|llama-cpp-python|torch|"
                   r"transformers|docker|requests|httpx)\b"),
        "That dependency belongs to a later milestone.",
    ),
    (
        re.compile(r"\b(huggingface-cli|hf)\s+download\b|\bwget\b.*\.gguf|\bcurl\b.*\.gguf"),
        "Model downloads are out of scope for Milestone 1.",
    ),
]

# Only guard the agent subproject's production package.
GUARDED_PATH = re.compile(r"local-agent/src/local_agent/.*\.py$")


def _block(reason: str) -> None:
    print(f"Milestone 1 scope guard: {reason}", file=sys.stderr)
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
            str(tool_input.get(key, ""))
            for key in ("content", "new_string", "new_str")
        )
        match = FORBIDDEN_IMPORTS.search(written)
        if match:
            _block(
                f"`{match.group(0).strip()}` introduces a capability the milestone "
                f"excludes (no filesystem, shell, network, or model runtime)."
            )

    sys.exit(0)


if __name__ == "__main__":
    main()
