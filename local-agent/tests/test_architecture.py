"""Repository-enforced capability boundaries.

The mission asks for boundaries enforced by the repository, not just by
prose. These tests parse the production package's own AST and fail the build
if a forbidden capability is ever introduced — a future edit that adds
`import subprocess`, `open(...)`, or an HTTP client breaks CI at this file
rather than at review time.

This is the layer that makes "no shell executor exists" a checked fact.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "local_agent"

# Everything Milestone 1 is permitted to import. Deliberately tiny: the
# controller needs JSON, dataclasses, typing, and pydantic. Nothing else.
ALLOWED_IMPORTS = frozenset(
    {
        "__future__",
        "json",
        "dataclasses",
        "enum",
        "typing",
        "collections",
        "collections.abc",
        "pydantic",
    }
)

# Capabilities explicitly out of scope for Milestone 1 (task §"hard_scope").
FORBIDDEN_IMPORTS = frozenset(
    {
        "os",
        "sys",
        "subprocess",
        "shutil",
        "pathlib",
        "glob",
        "tempfile",
        "io",
        "socket",
        "ssl",
        "http",
        "urllib",
        "requests",
        "httpx",
        "aiohttp",
        "sqlite3",
        "docker",
        "playwright",
        "selenium",
        "qdrant_client",
        "llama_cpp",
        "transformers",
        "torch",
        "openai",
        "anthropic",
        "mcp",
        "threading",
        "multiprocessing",
        "ctypes",
        "pickle",
        "importlib",
    }
)


def _production_modules() -> list[pathlib.Path]:
    return sorted(SRC.rglob("*.py"))


def _imported_roots(tree: ast.AST) -> set[str]:
    """Top-level module names imported by a file, ignoring relative imports."""
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        # level > 0 is an intra-package relative import, which is always allowed.
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_the_package_has_production_modules_to_check() -> None:
    assert len(_production_modules()) >= 8


@pytest.mark.parametrize("path", _production_modules(), ids=lambda p: p.name)
def test_no_module_imports_a_forbidden_capability(path: pathlib.Path) -> None:
    roots = _imported_roots(ast.parse(path.read_text()))
    assert not roots & FORBIDDEN_IMPORTS, f"{path.name} imports {roots & FORBIDDEN_IMPORTS}"


@pytest.mark.parametrize("path", _production_modules(), ids=lambda p: p.name)
def test_imports_stay_within_the_allowlist(path: pathlib.Path) -> None:
    roots = _imported_roots(ast.parse(path.read_text()))
    assert roots <= ALLOWED_IMPORTS, f"{path.name} imports {roots - ALLOWED_IMPORTS}"


@pytest.mark.parametrize("path", _production_modules(), ids=lambda p: p.name)
def test_no_dynamic_execution_or_file_access_primitives(path: pathlib.Path) -> None:
    """No `eval`, `exec`, `compile`, `__import__`, or `open` anywhere in production code."""
    forbidden_calls = {"eval", "exec", "compile", "__import__", "open", "input"}
    tree = ast.parse(path.read_text())
    used = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not used & forbidden_calls, f"{path.name} calls {used & forbidden_calls}"


def _code_without_docstrings(path: pathlib.Path) -> str:
    """Source with comments and docstrings stripped, so prose is not scanned.

    Documentation legitimately *names* the runtimes this package must not
    depend on ("no llama.cpp here"); only executable code and live string
    literals are evidence of an actual dependency.
    """
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        first = node.body[0] if node.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            node.body = node.body[1:] or [ast.Pass()]
    return ast.unparse(tree).lower()


def test_no_module_references_a_model_runtime_or_vendor_api() -> None:
    """The controller must stay independent of any specific LLM (spec 10 §10)."""
    banned = (
        "llama_cpp",
        "llamacpp",
        "gemma",
        "openai",
        "anthropic",
        "huggingface",
        "localhost",
        "http://",
        "https://",
        "127.0.0.1",
    )
    for path in _production_modules():
        code = _code_without_docstrings(path)
        for token in banned:
            assert token not in code, f"{path.name} references {token}"


def test_runtime_dependencies_are_pinned_and_minimal() -> None:
    pyproject = (SRC.parents[1] / "pyproject.toml").read_text()
    dependencies_block = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0]
    packages = [
        line.strip().strip('",') for line in dependencies_block.strip().splitlines() if line.strip()
    ]
    assert len(packages) == 1
    assert packages[0].startswith("pydantic>=")
    assert "<3" in packages[0]  # bounded, never an unpinned `latest`


def test_the_only_registered_tool_is_the_fake_file_search() -> None:
    from local_agent.wiring import build_default_registry

    registry = build_default_registry()
    assert registry.names == frozenset({"file_search"})

    spec = registry.get("file_search")
    assert spec is not None
    assert spec.destructive is False
    assert spec.requires_authorization is True
    assert spec.timeout_seconds > 0
    assert type(spec.executor).__name__ == "FakeFileSearchExecutor"
