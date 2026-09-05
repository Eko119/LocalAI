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

# The base grant every production module holds. Deliberately tiny: the
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


# Milestone 2 opened exactly one capability, to exactly one module.
#
# `workspace_fs.py` is the only production file that may reach a filesystem,
# so it is the only one granted `pathlib`. The grant is expressed per module
# rather than by widening ALLOWED_IMPORTS, because a global widening would
# silently let the controller, the policy gates, or the state machine acquire
# filesystem access later — which is precisely the drift this test exists to
# catch. Adding a module to this map should be a deliberate, reviewed act.
MODULE_IMPORT_GRANTS: dict[str, frozenset[str]] = {
    "workspace_fs.py": frozenset({"pathlib"}),
    # Milestone 3 opened network access to exactly one module. `asyncio` rides
    # along because the stdlib HTTP client is blocking and the round trip is
    # moved onto a worker thread; it is not itself a network capability.
    "http.py": frozenset({"urllib", "asyncio"}),
}

# Modules that must never touch a filesystem, whatever else changes. Listed
# by name so that deleting one from the map is visible in review.
FILESYSTEM_FREE_MODULES = frozenset(
    {
        "controller.py",
        "policy.py",
        "state_machine.py",
        "contracts.py",
        "registry.py",
        "events.py",
        "model_adapter.py",
        "wiring.py",
        "file_search.py",
    }
)

FILESYSTEM_MODULES = frozenset({"pathlib", "os", "shutil", "glob", "tempfile", "io", "fileinput"})

# Anything that can open a socket, directly or indirectly.
NETWORK_MODULES = frozenset(
    {
        "urllib",
        "socket",
        "ssl",
        "http",
        "ftplib",
        "smtplib",
        "telnetlib",
        "requests",
        "httpx",
        "aiohttp",
        "websockets",
        "grpc",
    }
)

# Modules that must never reach the network, whatever else changes. The model
# adapter is on this list deliberately: it builds and interprets payloads, and
# the socket belongs one layer below it, in the transport.
NETWORK_FREE_MODULES = frozenset(
    {
        "controller.py",
        "policy.py",
        "state_machine.py",
        "contracts.py",
        "registry.py",
        "events.py",
        "model_adapter.py",
        "model_transport.py",
        "model_service.py",
        "model_config.py",
        "wiring.py",
        "file_search.py",
        "workspace_fs.py",
    }
)

# Modules that legitimately deal in URLs. Everywhere else, a URL literal in
# production code means someone hard-coded an endpoint.
URL_BEARING_MODULES = frozenset({"model_config.py", "http.py"})


def _production_modules() -> list[pathlib.Path]:
    return sorted(SRC.rglob("*.py"))


def _grant(path: pathlib.Path) -> frozenset[str]:
    return MODULE_IMPORT_GRANTS.get(path.name, frozenset())


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
    forbidden = FORBIDDEN_IMPORTS - _grant(path)
    assert not roots & forbidden, f"{path.name} imports {roots & forbidden}"


@pytest.mark.parametrize("path", _production_modules(), ids=lambda p: p.name)
def test_imports_stay_within_the_allowlist(path: pathlib.Path) -> None:
    roots = _imported_roots(ast.parse(path.read_text()))
    allowed = ALLOWED_IMPORTS | _grant(path)
    assert roots <= allowed, f"{path.name} imports {roots - allowed}"


@pytest.mark.parametrize("name", sorted(NETWORK_FREE_MODULES))
def test_the_control_plane_cannot_touch_the_network(name: str) -> None:
    """Network access is one module's capability, not the control plane's.

    The controller decides whether a proposal executes; the transport speaks
    to the model service. Keeping the socket out of every module on this list
    means an adapter, a gate, or the state machine cannot quietly acquire a
    second channel to the outside world.
    """
    matches = [path for path in _production_modules() if path.name == name]
    assert matches, f"{name} is missing — update NETWORK_FREE_MODULES deliberately"
    for path in matches:
        roots = _imported_roots(ast.parse(path.read_text()))
        assert not roots & NETWORK_MODULES, f"{name} imports {roots & NETWORK_MODULES}"


def test_only_the_http_transport_holds_a_network_grant() -> None:
    """Exactly one module may reach the network, and this is its name."""
    granted = {name for name, grant in MODULE_IMPORT_GRANTS.items() if grant & NETWORK_MODULES}
    assert granted == {"http.py"}

    holders = [
        path.name
        for path in _production_modules()
        if _imported_roots(ast.parse(path.read_text())) & NETWORK_MODULES
    ]
    assert holders == ["http.py"]


def test_the_model_layer_cannot_touch_a_filesystem() -> None:
    """A model adapter has no business reading files, and structurally cannot."""
    for name in (
        "model_adapter.py",
        "model_service.py",
        "model_transport.py",
        "model_config.py",
        "http.py",
    ):
        matches = [path for path in _production_modules() if path.name == name]
        assert matches, f"{name} is missing"
        roots = _imported_roots(ast.parse(matches[0].read_text()))
        assert not roots & FILESYSTEM_MODULES, f"{name} imports {roots & FILESYSTEM_MODULES}"


def test_the_transport_cannot_reach_the_controller_authority_objects() -> None:
    """The transport sees bytes. It must not import the controller's authority.

    A transport that could import `RunContext`, the registry, or the state
    machine would be one refactor away from consulting or mutating them.
    """
    path = SRC / "transports" / "http.py"
    tree = ast.parse(path.read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[-1])
        elif isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[-1] for alias in node.names)

    for forbidden in ("controller", "policy", "registry", "state_machine", "wiring", "contracts"):
        assert forbidden not in imported, f"transport imports {forbidden}"


def test_the_model_layer_cannot_mutate_controller_authority() -> None:
    """No model-layer module may construct or write controller authority objects.

    `RunContext` and `ToolRegistry` are frozen and mutation-free respectively,
    so this is belt and braces — but it catches the attempt at the point a
    developer writes it, rather than at the point it would have failed.
    """
    authority_names = {"RunContext", "ToolRegistry", "ToolSpec", "Run", "State", "TRANSITIONS"}
    for name in (
        "model_adapter.py",
        "model_service.py",
        "model_transport.py",
        "model_config.py",
        "http.py",
    ):
        matches = [path for path in _production_modules() if path.name == name]
        assert matches, f"{name} is missing"
        tree = ast.parse(matches[0].read_text())
        referenced = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert not referenced & authority_names, (
            f"{name} references controller authority {referenced & authority_names}"
        )


@pytest.mark.parametrize("name", sorted(FILESYSTEM_FREE_MODULES))
def test_the_control_plane_cannot_touch_a_filesystem(name: str) -> None:
    """The controller and its gates must never acquire filesystem access.

    This is the structural half of "the model never receives filesystem
    authority": the components that make authorization decisions physically
    cannot perform the operation they are authorizing.
    """
    matches = [path for path in _production_modules() if path.name == name]
    assert matches, f"{name} is missing — update FILESYSTEM_FREE_MODULES deliberately"
    for path in matches:
        roots = _imported_roots(ast.parse(path.read_text()))
        assert not roots & FILESYSTEM_MODULES, f"{name} imports {roots & FILESYSTEM_MODULES}"


def test_only_the_filesystem_executor_holds_a_filesystem_grant() -> None:
    """Exactly one module may reach a filesystem, and this is its name."""
    granted = {name for name, grant in MODULE_IMPORT_GRANTS.items() if grant & FILESYSTEM_MODULES}
    assert granted == {"workspace_fs.py"}

    holders = [
        path.name
        for path in _production_modules()
        if _imported_roots(ast.parse(path.read_text())) & FILESYSTEM_MODULES
    ]
    assert holders == ["workspace_fs.py"]


def test_the_filesystem_executor_exposes_no_mutation_primitive() -> None:
    """Read-only enforced against the AST, not merely asserted in a docstring."""
    path = SRC / "executors" / "workspace_fs.py"
    tree = ast.parse(path.read_text())

    mutators = {
        "write_text",
        "write_bytes",
        "unlink",
        "rmdir",
        "mkdir",
        "rename",
        "replace",
        "chmod",
        "lchmod",
        "chown",
        "touch",
        "symlink_to",
        "hardlink_to",
        "link_to",
        "rmtree",
        "copy",
        "copy2",
        "copyfile",
        "move",
        "remove",
        "makedirs",
        "truncate",
    }
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not called & mutators, f"filesystem executor calls {called & mutators}"


def test_the_filesystem_executor_only_opens_for_reading() -> None:
    """Every `.open(...)` in the executor passes a literal read-only mode."""
    path = SRC / "executors" / "workspace_fs.py"
    tree = ast.parse(path.read_text())

    modes: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "open":
            continue
        assert node.args, "open() must pass an explicit literal mode"
        first = node.args[0]
        assert isinstance(first, ast.Constant) and isinstance(first.value, str), (
            "open() mode must be a string literal, not a computed value"
        )
        modes.append(first.value)

    assert modes, "expected at least one read in the filesystem executor"
    for mode in modes:
        assert mode.startswith("r"), f"non-read open mode: {mode!r}"
        assert "+" not in mode, f"read/write open mode: {mode!r}"


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
            if token in {"http://", "https://"} and path.name in URL_BEARING_MODULES:
                # The config validates URL schemes and the transport builds a
                # request URL; naming the scheme there is the job, not a
                # hard-coded endpoint. Neither module names a vendor runtime.
                continue
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


def test_the_filesystem_registry_holds_exactly_the_two_read_only_tools(
    tmp_path: pathlib.Path,
) -> None:
    """Milestone 2 grants two capabilities and no more (task §13)."""
    from local_agent.wiring import build_filesystem_registry, build_physical_roots

    (tmp_path / "workspace").mkdir()
    (tmp_path / "knowledge").mkdir()
    roots = build_physical_roots(
        {"workspace": tmp_path / "workspace", "knowledge": tmp_path / "knowledge"}
    )
    registry = build_filesystem_registry(roots)

    assert registry.names == frozenset({"workspace.read", "workspace.list"})
    for name in registry.names:
        spec = registry.get(name)
        assert spec is not None
        assert spec.destructive is False
        assert spec.requires_authorization is True
        assert spec.timeout_seconds > 0

    for forbidden in ("workspace.write", "workspace.delete", "workspace.mkdir", "shell", "exec"):
        assert registry.get(forbidden) is None
