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

from local_agent.state_machine import State

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
    # Milestone 5 opened durable storage to exactly one module. `fcntl` is the
    # advisory lock that stops two live recoveries of the same run.
    "journal.py": frozenset({"os", "fcntl", "pathlib"}),
    # Hashing for content-addressed execution identity and record integrity,
    # and `uuid` for run identity. Neither is a capability: no I/O, no
    # network, no ambient state — `uuid4` reads the OS random source only.
    "records.py": frozenset({"hashlib", "uuid"}),
    # Milestone 7. `hashlib` content-addresses a capability the same way
    # `records.py` content-addresses an execution; `types` supplies
    # `MappingProxyType`, which is what makes the registry's map read-only
    # rather than a plain dict anyone could write through. Neither performs
    # I/O, opens a socket, or reads ambient state.
    "registry.py": frozenset({"hashlib", "types"}),
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

FILESYSTEM_MODULES = frozenset(
    {"pathlib", "os", "shutil", "glob", "tempfile", "io", "fileinput", "fcntl"}
)

# The two modules allowed to touch a filesystem, and why each one is.
# They are different capabilities that happen to share a syscall surface:
# one resolves a *model-requested* path under an authorized root, the
# other writes *controller-owned* state to an operator-configured file.
FILESYSTEM_GRANT_HOLDERS = frozenset({"workspace_fs.py", "journal.py"})

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
        "records.py",
        "journal.py",
        "recovery.py",
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


def test_only_the_declared_modules_hold_a_filesystem_grant() -> None:
    """Filesystem access is confined to two named modules, and no others."""
    granted = {name for name, grant in MODULE_IMPORT_GRANTS.items() if grant & FILESYSTEM_MODULES}
    assert granted == set(FILESYSTEM_GRANT_HOLDERS)

    holders = {
        path.name
        for path in _production_modules()
        if _imported_roots(ast.parse(path.read_text())) & FILESYSTEM_MODULES
    }
    assert holders == set(FILESYSTEM_GRANT_HOLDERS)


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


# Ways TLS verification gets disabled. None may appear anywhere in the
# project — not in production code, and not "just for the live test".
TLS_WEAKENING_TOKENS = (
    "verify=false",
    "verify = false",
    "_create_unverified_context",
    "cert_none",
    "check_hostname = false",
    "check_hostname=false",
    "_create_default_https_context",
    "pythonhttpsverify",
    "insecureskipverify",
    "sslcontext(ssl.protocol",
)


# This module necessarily contains every forbidden token as *data* — it is
# the file that lists them. Excluding exactly one self-referential file keeps
# the scan honest; `test_the_scan_excludes_only_itself` pins that it stays one.
SCAN_EXCLUSIONS = frozenset({"test_architecture.py"})


def _all_project_python() -> list[pathlib.Path]:
    """Production source and tests alike — a bypass hidden in a test still counts."""
    root = SRC.parents[1]
    return sorted(
        path
        for path in root.rglob("*.py")
        if ".venv" not in path.parts
        and "__pycache__" not in path.parts
        and path.name not in SCAN_EXCLUSIONS
    )


def test_the_scan_excludes_only_itself() -> None:
    """The exclusion list must not quietly grow into a hiding place."""
    assert SCAN_EXCLUSIONS == frozenset({"test_architecture.py"})
    scanned = {path.name for path in _all_project_python()}
    assert "http.py" in scanned and "controller.py" in scanned
    assert "test_live_localai.py" in scanned and "live_support.py" in scanned


def test_tls_verification_is_never_weakened_anywhere() -> None:
    """No certificate-check bypass, in source or in tests.

    A live integration test that failed against a self-signed certificate
    would be trivially "fixed" by disabling verification. That fix is a
    security downgrade hidden in a test file, so it is banned by a check that
    covers tests too, not only `src/`.
    """
    for path in _all_project_python():
        lowered = path.read_text().lower()
        for token in TLS_WEAKENING_TOKENS:
            assert token not in lowered, (
                f"{path.name} appears to weaken TLS verification: {token!r}"
            )


def test_no_module_disables_certificate_validation_via_environment() -> None:
    """`PYTHONHTTPSVERIFY=0` and friends must not be set by the project."""
    for path in _all_project_python():
        text = path.read_text()
        for token in ("PYTHONHTTPSVERIFY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            if f'"{token}"' in text or f"'{token}'" in text:
                raise AssertionError(f"{path.name} manipulates TLS trust via {token}")


def test_the_network_boundary_check_actually_catches_a_violation() -> None:
    """Adversarial test of the test: poison a module and prove the check fails.

    A boundary assertion that could never fail is worthless. This mutates a
    copy of the controller's source to import a network library and confirms
    the same predicate the real test uses rejects it.
    """
    controller = SRC / "controller.py"
    poisoned = "import urllib.request\n" + controller.read_text()
    roots = _imported_roots(ast.parse(poisoned))

    assert roots & NETWORK_MODULES, "the poisoned module was not detected"
    # And the unmodified original is clean, so the check is not simply always true.
    assert not _imported_roots(ast.parse(controller.read_text())) & NETWORK_MODULES


def test_the_filesystem_boundary_check_actually_catches_a_violation() -> None:
    policy = SRC / "policy.py"
    poisoned = "import pathlib\n" + policy.read_text()
    assert _imported_roots(ast.parse(poisoned)) & FILESYSTEM_MODULES
    assert not _imported_roots(ast.parse(policy.read_text())) & FILESYSTEM_MODULES


def test_production_source_reads_no_environment_variable() -> None:
    """Configuration is constructed by wiring, never picked up ambiently.

    Env reading lives in the test/ops layer (`tests/live_support.py`). Keeping
    it out of `src/` is why `os` is not in any production import grant, and it
    means a deployment cannot be reconfigured by an environment variable that
    no one declared.
    """
    for path in _production_modules():
        text = path.read_text()
        for token in ("os.environ", "getenv", "environ["):
            assert token not in text, f"{path.name} reads the environment via {token}"


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


# ===========================================================================
# Milestone 4: the twenty architectural invariants, stated in one place
# ===========================================================================
#
# Each of these is covered in depth by a behavioural test elsewhere. Gathering
# the structural half here gives one file a reader can check the architecture
# against, and makes a silent erosion of any single invariant fail loudly.


def test_invariant_the_controller_is_the_only_authority() -> None:
    """1, 4: authority objects are constructed by wiring, not by the model layer."""
    controller = (SRC / "controller.py").read_text()
    assert "RunContext" in controller  # the controller reads authority
    for name in ("model_service.py", "model_transport.py", "transports/http.py"):
        text = (SRC / name).read_text()
        assert "RunContext" not in text
        assert "evaluate_policy" not in text
        assert "authorize(" not in text


def test_invariant_model_output_is_untrusted_data() -> None:
    """2: the only channel the parser reads is the structured one."""
    import inspect

    from local_agent.controller import parse_candidate

    source = inspect.getsource(parse_candidate)
    assert "structured_output" in source
    assert "response.narrative" not in source
    assert "response.reasoning" not in source


def test_invariant_the_transport_holds_no_controller_authority() -> None:
    """3, 10: the transport imports bytes-level types only."""
    text = (SRC / "transports" / "http.py").read_text()
    for forbidden in ("Controller", "RunContext", "ToolRegistry", "State", "TRANSITIONS"):
        assert forbidden not in text


@pytest.mark.parametrize(
    "setting",
    ["base_url", "api_key", "model", "timeout_seconds", "max_response_bytes"],
)
def test_invariant_the_model_cannot_supply_transport_configuration(setting: str) -> None:
    """5, 6: no configuration field is reachable from a model-facing contract."""
    from local_agent.contracts import ModelResponse, RawToolCall

    for model in (ModelResponse, RawToolCall):
        assert setting not in model.model_fields


def test_invariant_budget_policy_and_roots_are_frozen_authority() -> None:
    """7, 8, 9, 10: the model cannot widen any of them, structurally."""
    import dataclasses

    from local_agent.model_config import ModelServiceConfig
    from local_agent.policy import RunContext

    for instance, field_name, value in (
        (RunContext(run_id="x"), "max_attempts", 999),
        (RunContext(run_id="x"), "authorized_roots", frozenset({"workspace"})),
        (RunContext(run_id="x"), "filesystem", None),
        (ModelServiceConfig(base_url="http://h:1", model="m"), "base_url", "http://evil"),
    ):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(instance, field_name, value)


def test_invariant_the_model_cannot_select_a_state_transition() -> None:
    """11: no model-facing contract carries a state, and the table is fixed."""
    from local_agent.contracts import ModelRequest, ModelResponse, RawToolCall
    from local_agent.state_machine import TRANSITIONS, State

    for model in (ModelResponse, RawToolCall, ModelRequest):
        assert "state" not in model.model_fields
    predecessors = {source for source, targets in TRANSITIONS.items() if State.EXECUTE in targets}
    assert predecessors == {State.POLICY_CHECK}


def test_invariant_no_semantic_retry_below_the_controller() -> None:
    """16, 17, 18: neither adapter nor transport contains a retry loop."""
    for name in ("model_service.py", "model_transport.py", "transports/http.py"):
        # Docstrings legitimately explain *why* there is no retry loop, so the
        # scan looks at executable code only — the same treatment the vendor
        # reference check uses.
        code = _code_without_docstrings(SRC / name)
        for token in ("for attempt", "while attempt", "retries", "max_retries", "backoff"):
            assert token not in code, f"{name} appears to retry: {token!r}"


def test_invariant_normal_ci_does_not_require_localai() -> None:
    """19: the CI workflow names no model service and no live gate."""
    workflow = (SRC.parents[2] / ".github" / "workflows" / "local-agent.yml").read_text()
    for token in ("LOCAL_AGENT_LIVE_MODEL", "LOCALAI_MODEL", "LOCALAI_BASE_URL", "localai/localai"):
        assert token not in workflow, f"CI references {token}"
    assert "uv run pytest -q" in workflow


def test_invariant_deterministic_replay_never_touches_live_inference() -> None:
    """20: the replay suite imports no live transport and no environment."""
    text = (SRC.parents[1] / "tests" / "test_determinism.py").read_text()
    assert "HttpModelTransport" not in text
    assert "os.environ" not in text
    assert "ScriptedTransport" in text or "build_model_harness" in text


# ===========================================================================
# Milestone 5: persistence ownership
# ===========================================================================
#
# Persistence is a controller-side capability. The model layer must not be
# able to reach it, tools must not be able to mutate it, and the durable
# store must not acquire a second capability of its own.

PERSISTENCE_MODULES = frozenset({"records.py", "journal.py", "recovery.py"})

MODEL_LAYER_MODULES = frozenset(
    {"model_adapter.py", "model_service.py", "model_transport.py", "model_config.py", "http.py"}
)


def _intra_package_imports(path: pathlib.Path) -> set[str]:
    """Module names imported from within this package, relative or absolute."""
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.update(node.module.split("."))
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name.split(".")[-1] for alias in node.names)
    return names


@pytest.mark.parametrize("name", sorted(MODEL_LAYER_MODULES))
def test_the_model_layer_cannot_reach_persistence(name: str) -> None:
    """A model adapter must not be able to read or write durable state.

    The model proposes; the controller decides and records. If the adapter
    could touch the journal, model-adjacent code would sit on the same side
    of the boundary as the controller's own memory of what it authorized.
    """
    matches = [path for path in _production_modules() if path.name == name]
    assert matches, f"{name} is missing"
    imported = _intra_package_imports(matches[0])
    for forbidden in ("persistence", "journal", "records", "recovery"):
        assert forbidden not in imported, f"{name} imports {forbidden}"


@pytest.mark.parametrize("name", ["file_search.py", "workspace_fs.py"])
def test_tools_cannot_reach_persistence(name: str) -> None:
    """An executor must not be able to write the record of its own execution."""
    matches = [path for path in _production_modules() if path.name == name]
    assert matches, f"{name} is missing"
    imported = _intra_package_imports(matches[0])
    for forbidden in ("persistence", "journal", "records", "recovery"):
        assert forbidden not in imported, f"{name} imports {forbidden}"


@pytest.mark.parametrize("name", ["records.py", "journal.py"])
def test_the_durable_store_holds_no_controller_authority(name: str) -> None:
    """The store serializes bytes; it does not decide anything."""
    matches = [path for path in _production_modules() if path.name == name]
    assert matches, f"{name} is missing"
    imported = _intra_package_imports(matches[0])
    for forbidden in ("controller", "policy", "registry", "state_machine", "wiring"):
        assert forbidden not in imported, f"{name} imports {forbidden}"


def test_persistence_never_reaches_the_model_or_the_network() -> None:
    for name in sorted(PERSISTENCE_MODULES):
        matches = [path for path in _production_modules() if path.name == name]
        assert matches, f"{name} is missing"
        roots = _imported_roots(ast.parse(matches[0].read_text()))
        assert not roots & NETWORK_MODULES, f"{name} reaches the network"
        imported = _intra_package_imports(matches[0])
        for forbidden in ("model_adapter", "model_service", "model_transport", "model_config"):
            assert forbidden not in imported, f"{name} imports {forbidden}"


def test_recovery_reads_no_environment_and_opens_no_file() -> None:
    """Recovery is pure: records in, a plan out. It cannot go looking."""
    path = SRC / "recovery.py"
    roots = _imported_roots(ast.parse(path.read_text()))
    assert not roots & FILESYSTEM_MODULES
    assert not roots & NETWORK_MODULES
    assert "os.environ" not in path.read_text()


def test_the_persistence_boundary_check_actually_catches_a_violation() -> None:
    """Adversarial: a model module that imported the journal must be caught."""
    poisoned = (
        "from .persistence.journal import RunJournal\n" + (SRC / "model_service.py").read_text()
    )
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        candidate = pathlib.Path(directory) / "model_service.py"
        candidate.write_text(poisoned)
        assert "journal" in _intra_package_imports(candidate)

    # And the real module is clean, so the check is not trivially true.
    assert "journal" not in _intra_package_imports(SRC / "model_service.py")


def test_only_the_journal_writes_durable_state() -> None:
    """Exactly one module opens a file for writing or forces it to disk.

    Read-only opens are not writes: `workspace_fs.py` legitimately opens files
    in mode "rb", which `test_the_filesystem_executor_only_opens_for_reading`
    pins separately. What this asserts is narrower and is the property that
    matters for durable state — only the journal can create or extend it.
    """
    writers: list[str] = []
    for path in _production_modules():
        tree = ast.parse(path.read_text())
        writes = False
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            attribute = node.func.attr
            if attribute in {"write_text", "write_bytes", "fsync", "truncate"}:
                writes = True
            elif attribute == "open":
                mode = node.args[0] if node.args else None
                literal = mode.value if isinstance(mode, ast.Constant) else ""
                if not isinstance(literal, str) or any(flag in literal for flag in "wa+"):
                    writes = True
        if writes:
            writers.append(path.name)
    assert writers == ["journal.py"]


# ===========================================================================
# Milestone 6: the operator control plane
#
# An operator is trusted to *decide* and never trusted to *act*. These tests
# make that structural rather than procedural: the module that handles operator
# input has no path to an executor, no path to the model, and no way to mutate
# any authority object.

OPERATOR_MODULE = "operator.py"

# Every object that holds authority. The operator layer may read a plan
# derived from these; it may never assign to one.
AUTHORITY_ATTRIBUTES = frozenset(
    {
        "max_attempts",
        "authorized_tools",
        "authorized_roots",
        "allow_destructive",
        "max_results_ceiling",
        "filesystem",
        "side_effect_free",
        "requires_authorization",
        "destructive",
        "executor",
        "args_schema",
        "result_schema",
        "timeout_seconds",
    }
)


def _module(name: str) -> pathlib.Path:
    matches = [path for path in _production_modules() if path.name == name]
    assert matches, f"{name} is missing"
    return matches[0]


def _attribute_assignments(path: pathlib.Path) -> set[str]:
    """Attribute names this module assigns to, anywhere."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign | ast.AugAssign):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Attribute):
                names.add(target.attr)
    return names


def _attribute_reads(path: pathlib.Path) -> set[str]:
    """Attribute names this module reads, anywhere."""
    return {
        node.attr
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.Attribute)
    }


def _constructed_types(path: pathlib.Path) -> set[str]:
    """Type names this module *calls* — i.e. constructs — ignoring definitions.

    Deliberately not a text search: `records.py` defines the record class, and
    a substring scan would count the `class` statement as a construction.
    """
    return {
        node.func.id
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }


def _called_methods(path: pathlib.Path) -> set[str]:
    return {
        node.func.attr
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }


def test_the_operator_layer_cannot_invoke_an_executor() -> None:
    """No `.execute(` and no `.executor` anywhere in the operator module.

    The threat model's first prohibition — "the operator must not be able to
    invoke an executor" — is checked here as an absence rather than as a guard,
    because a guard can be removed by the same edit that adds the call.
    """
    path = _module(OPERATOR_MODULE)
    assert "execute" not in _called_methods(path)
    assert "executor" not in _attribute_reads(path)


def test_the_operator_layer_cannot_reach_the_controller() -> None:
    """Deciding and acting live in different modules, and only one can act."""
    imported = _intra_package_imports(_module(OPERATOR_MODULE))
    for forbidden in ("controller", "wiring"):
        assert forbidden not in imported, f"operator.py imports {forbidden}"


def test_the_operator_layer_cannot_reach_the_model_or_the_network() -> None:
    """Task 10: no part of recovery may consult a model about its own safety."""
    path = _module(OPERATOR_MODULE)
    assert not _imported_roots(ast.parse(path.read_text())) & NETWORK_MODULES
    imported = _intra_package_imports(path)
    for forbidden in ("model_adapter", "model_service", "model_transport", "model_config"):
        assert forbidden not in imported, f"operator.py imports {forbidden}"


def test_the_operator_layer_cannot_touch_a_filesystem() -> None:
    path = _module(OPERATOR_MODULE)
    assert not _imported_roots(ast.parse(path.read_text())) & FILESYSTEM_MODULES


@pytest.mark.parametrize("name", sorted(AUTHORITY_ATTRIBUTES))
def test_the_operator_layer_assigns_to_no_authority_attribute(name: str) -> None:
    """It cannot change the budget, the grants, the ToolSpec, or the roots.

    Every one of these is frozen at runtime as well, so this is the second
    lock rather than the only one — but a frozen dataclass raises where an AST
    check *prevents*, and prevention is what a reviewer can see.
    """
    assert name not in _attribute_assignments(_module(OPERATOR_MODULE))


def test_the_operator_boundary_check_actually_catches_a_violation() -> None:
    """Adversarial test of the test: an operator module that executed must fail."""
    poisoned = "def go(spec):\n    return spec.executor.execute(None)\n"
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        candidate = pathlib.Path(directory) / "operator.py"
        candidate.write_text(poisoned)
        assert "execute" in _called_methods(candidate)
        assert "executor" in _attribute_reads(candidate)

    # And the real module is clean, so the check is not trivially true.
    assert "execute" not in _called_methods(_module(OPERATOR_MODULE))


def test_the_authority_assignment_check_actually_catches_a_violation() -> None:
    poisoned = "def widen(run):\n    run.max_attempts = 999\n"
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        candidate = pathlib.Path(directory) / "operator.py"
        candidate.write_text(poisoned)
        assert "max_attempts" in _attribute_assignments(candidate)


def test_recovery_cannot_reach_the_model_the_network_or_a_filesystem() -> None:
    """Restated for Milestone 6 now that recovery also runs the gates."""
    path = _module("recovery.py")
    roots = _imported_roots(ast.parse(path.read_text()))
    assert not roots & NETWORK_MODULES
    assert not roots & FILESYSTEM_MODULES
    imported = _intra_package_imports(path)
    for forbidden in ("model_adapter", "model_service", "model_transport", "controller"):
        assert forbidden not in imported, f"recovery.py imports {forbidden}"


def test_recovery_does_not_bypass_the_gates_it_reports_on() -> None:
    """A plan's `authorization_valid` comes from the real gates, not a copy.

    If recovery re-implemented authorization it would drift from the gate the
    controller actually applies, and a plan could offer a resume that EXECUTE
    would refuse — or worse, the reverse.
    """
    source = _code_without_docstrings(_module("recovery.py"))
    assert "authorize(" in source
    assert "evaluate_policy(" in source


def test_the_recovery_planner_never_executes() -> None:
    """The planner identifies what is safe; it does not do it."""
    path = _module("recovery.py")
    assert "execute" not in _called_methods(path)
    assert "executor" not in _attribute_reads(path)


def test_persistence_cannot_invoke_an_executor_or_a_model() -> None:
    for name in sorted(PERSISTENCE_MODULES):
        path = _module(name)
        assert "execute" not in _called_methods(path), f"{name} calls execute"
        assert "executor" not in _attribute_reads(path), f"{name} reaches an executor"


def test_only_the_controller_persists_an_operator_decision() -> None:
    """Recording a decision is an act, and acts belong to the controller.

    In particular the operator module must not be able to write its own
    decision: that would let the control plane manufacture the evidence that
    a human was asked.
    """
    writers = [
        path.name
        for path in _production_modules()
        if "OperatorDecisionRecorded" in _constructed_types(path)
    ]
    assert writers == ["controller.py"]


def test_the_operator_decision_contract_exposes_no_execution_fields() -> None:
    """Read the schema, not the docs: the type must have no way to say "run X"."""
    from local_agent.operator import OperatorDecision

    fields = set(OperatorDecision.model_fields)
    assert fields == {
        "schema_version",
        "run_id",
        "plan_id",
        "action",
        "decision_sequence",
        "reason_code",
        "expected_execution_id",
    }
    assert OperatorDecision.model_config["extra"] == "forbid"
    assert OperatorDecision.model_config["frozen"] is True


def test_a_terminal_run_offers_no_action_in_any_disposition() -> None:
    """Terminality is enforced in the action table itself, not at the call site."""
    from local_agent.recovery import _available_actions

    assert _available_actions("terminal", authorization_valid=True, decisions=0) == ()


def test_only_a_repeatable_pending_execution_is_ever_offered_a_resume() -> None:
    """Exhaustive over the disposition space, because the space is small."""
    from local_agent.recovery import Disposition, _available_actions

    dispositions: tuple[Disposition, ...] = (
        "terminal",
        "no_execution_authorized",
        "execution_completed",
        "execution_pending_repeatable",
        "execution_unknown",
    )
    offered = {
        (disposition, valid): "resume"
        in _available_actions(disposition, authorization_valid=valid, decisions=0)
        for disposition in dispositions
        for valid in (True, False)
    }
    assert {key for key, value in offered.items() if value} == {
        ("execution_pending_repeatable", True)
    }


# The hook in `.claude/hooks/` is advisory; this is the enforcement. There must
# be no bypass mechanism in production source under any spelling — no flag, no
# keyword argument, no attribute, no environment switch.
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


def _identifiers_defined_or_bound(path: pathlib.Path) -> set[str]:
    """Names this module defines, binds, parameterises, or assigns as attributes.

    Deliberately not a text scan: the package's own docstrings say things like
    "turns a denial into a bypass tutorial" and "assumed unsafe to repeat", and
    a substring search flags those. What matters is whether a *name* exists.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
            arguments = getattr(node, "args", None)
            if arguments is not None:
                for group in (
                    arguments.posonlyargs,
                    arguments.args,
                    arguments.kwonlyargs,
                ):
                    names.update(argument.arg for argument in group)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
    return names


@pytest.mark.parametrize("path", _production_modules(), ids=lambda p: p.name)
def test_no_module_offers_a_bypass_mechanism(path: pathlib.Path) -> None:
    """No `--force`, `--unsafe`, `--bypass`, `--superuser`, or equivalent.

    Split on `_` so `bypass_policy`, `allow_unsafe` and `FORCE_RESUME` are all
    caught while `enforce` and `reinforce` are not — those contain a banned
    word as a substring but never as a part, which is the distinction that
    separates a bypass from ordinary English.
    """
    offenders = {
        name
        for name in _identifiers_defined_or_bound(path)
        if {part for part in name.lower().split("_") if part} & BYPASS_WORDS
    }
    assert not offenders, f"{path.name} defines a bypass-shaped name: {sorted(offenders)}"


def test_the_bypass_check_actually_catches_a_violation() -> None:
    """Adversarial: a controller that took a `force` flag must fail the check."""
    poisoned = "async def recover(self, decision, force: bool = False):\n    return force\n"
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        candidate = pathlib.Path(directory) / "controller.py"
        candidate.write_text(poisoned)
        names = _identifiers_defined_or_bound(candidate)
        assert "force" in names

    # And a legitimate near-miss is not caught, so the check is not a word ban.
    with tempfile.TemporaryDirectory() as directory:
        innocent = pathlib.Path(directory) / "policy.py"
        innocent.write_text("def enforce(rule):\n    return reinforce(rule)\n")
        names = _identifiers_defined_or_bound(innocent)
        assert not {
            name
            for name in names
            if {part for part in name.lower().split("_") if part} & BYPASS_WORDS
        }


# ===========================================================================
# Milestone 7: the capability contract and the tool-authoring boundary
#
# The question is "what stops a capability from becoming an authority?", and
# the answers below are structural: an executor module cannot reach the objects
# that hold authority, and the ownership of every authority-bearing property is
# asserted rather than described.

EXECUTOR_MODULES = frozenset({"file_search.py", "workspace_fs.py"})

# Modules an executor must never reach at all. Each would let the thing being
# governed take part in governing it.
AUTHORITY_MODULES = frozenset(
    {"controller", "wiring", "recovery", "operator", "journal", "state_machine"}
)

# `policy` is deliberately absent from that list, and the distinction is worth
# stating rather than smoothing over. `workspace_fs.py` imports
# `FilesystemLimits`, `DEFAULT_FILESYSTEM_LIMITS` and `LEGAL_ROOT_IDS` — a
# frozen ceiling object that trusted wiring hands it, and a constant. Enforcing
# a limit someone else set is the executor's job; *deciding* one is not. So the
# ban is on the deciding names rather than on the module, which is a narrower
# and more honest boundary than "no policy import".
FORBIDDEN_POLICY_NAMES = frozenset({"RunContext", "authorize", "evaluate_policy", "Decision"})


@pytest.mark.parametrize("name", sorted(EXECUTOR_MODULES))
def test_an_executor_module_cannot_reach_any_authority(name: str) -> None:
    """An executor acts; it does not decide whether it may.

    The registry is the one deliberate module-level exception: an executor
    imports it for `ToolSpec` and the two exception types it raises. That is
    the contract it implements, not authority it holds —
    `test_an_executor_module_never_constructs_a_registry_or_a_run_context`
    pins the difference.
    """
    imported = _intra_package_imports(_module(name))
    for forbidden in sorted(AUTHORITY_MODULES):
        assert forbidden not in imported, f"{name} imports {forbidden}"


@pytest.mark.parametrize("name", sorted(EXECUTOR_MODULES))
def test_an_executor_module_cannot_reach_a_gate_or_a_run_context(name: str) -> None:
    """The narrower half: enforcing a ceiling is allowed, deciding is not."""
    path = _module(name)
    imported = _intra_package_imports(path)
    reachable = imported | _attribute_reads(path) | _called_methods(path)
    for forbidden in sorted(FORBIDDEN_POLICY_NAMES):
        assert forbidden not in reachable, f"{name} reaches {forbidden}"


def test_the_gate_reachability_check_actually_catches_a_violation() -> None:
    """Adversarial: an executor that authorized itself must be caught."""
    import tempfile

    poisoned = (
        "from ..policy import authorize\n\n\ndef run(spec, args, ctx):\n"
        "    return authorize(spec, args, ctx)\n"
    )
    with tempfile.TemporaryDirectory() as directory:
        candidate = pathlib.Path(directory) / "workspace_fs.py"
        candidate.write_text(poisoned)
        reachable = (
            _intra_package_imports(candidate)
            | _attribute_reads(candidate)
            | _called_methods(candidate)
        )
        assert reachable & FORBIDDEN_POLICY_NAMES

    real = _module("workspace_fs.py")
    assert (
        not (_intra_package_imports(real) | _attribute_reads(real) | _called_methods(real))
        & FORBIDDEN_POLICY_NAMES
    )


@pytest.mark.parametrize("name", sorted(EXECUTOR_MODULES))
def test_an_executor_module_never_constructs_a_registry_or_a_run_context(name: str) -> None:
    """Implementing the contract is not the same as defining it."""
    constructed = _constructed_types(_module(name))
    for forbidden in ("ToolRegistry", "RunContext", "Controller", "RunJournal"):
        assert forbidden not in constructed, f"{name} constructs {forbidden}"


@pytest.mark.parametrize("name", sorted(EXECUTOR_MODULES))
def test_an_executor_module_assigns_to_no_authority_attribute(name: str) -> None:
    assert not _attribute_assignments(_module(name)) & AUTHORITY_ATTRIBUTES


def test_the_executor_boundary_check_actually_catches_a_violation() -> None:
    """Adversarial: an executor that imported the controller must be caught."""
    import tempfile

    poisoned = (
        "from ..controller import Controller\n" + (SRC / "executors" / "file_search.py").read_text()
    )
    with tempfile.TemporaryDirectory() as directory:
        candidate = pathlib.Path(directory) / "file_search.py"
        candidate.write_text(poisoned)
        assert "controller" in _intra_package_imports(candidate)

    assert "controller" not in _intra_package_imports(SRC / "executors" / "file_search.py")


def test_no_executor_module_writes_durable_state_or_calls_a_model() -> None:
    """Only the controller records what happened, and only it asks the model."""
    for name in sorted(EXECUTOR_MODULES):
        constructed = _constructed_types(_module(name))
        for forbidden in (
            "ExecutionAuthorized",
            "ExecutionCompleted",
            "RunTerminal",
            "RunStarted",
            "OperatorDecisionRecorded",
        ):
            assert forbidden not in constructed, f"{name} constructs {forbidden}"
        assert "chat" not in _called_methods(_module(name)), f"{name} calls a model"


def test_only_the_controller_invokes_an_executor() -> None:
    """`.executor` is reachable from exactly one production module.

    The registry defines the field and recovery re-resolves specs, so the check
    is on *reaching the attribute*, which is what invoking one requires.
    """
    reachers = [
        path.name
        for path in _production_modules()
        if "executor" in _attribute_reads(path) and path.name != "registry.py"
    ]
    assert reachers == ["controller.py"]


def test_the_capability_contract_is_not_reachable_from_the_model_layer() -> None:
    """An adapter maps wire fields; it has no business defining capabilities."""
    for name in sorted(MODEL_LAYER_MODULES):
        constructed = _constructed_types(_module(name))
        for forbidden in ("ToolSpec", "ToolRegistry"):
            assert forbidden not in constructed, f"{name} constructs {forbidden}"


def test_only_trusted_wiring_and_capability_builders_construct_a_registry() -> None:
    """Registration is assembly-time, in named places, not anywhere convenient."""
    builders = [
        path.name for path in _production_modules() if "ToolRegistry" in _constructed_types(path)
    ]
    assert sorted(builders) == ["wiring.py"]


def test_only_capability_builders_construct_a_toolspec() -> None:
    definers = [
        path.name for path in _production_modules() if "ToolSpec" in _constructed_types(path)
    ]
    assert sorted(definers) == ["file_search.py", "workspace_fs.py"]


# ---------------------------------------------------------------------------
# The authority matrix, encoded rather than described
# ---------------------------------------------------------------------------
#
# Every row names one authority-bearing property and the single component that
# owns it. A property with two authoritative writers is an authority leak, so
# the matrix is asserted by behaviour below rather than left in a document.


def test_the_authority_matrix_holds() -> None:
    """One assertion per row of the matrix in docs/milestone-7-decisions.md."""
    import dataclasses

    from local_agent.contracts import RETRYABLE_CODES, RawToolCall
    from local_agent.executors.file_search import FakeFileSearchExecutor
    from local_agent.operator import OperatorDecision
    from local_agent.persistence.records import derive_execution_id
    from local_agent.policy import RunContext
    from local_agent.registry import SideEffect, ToolRegistry, ToolSpec
    from local_agent.state_machine import TRANSITIONS
    from local_agent.wiring import build_default_registry

    registry = build_default_registry(FakeFileSearchExecutor())
    spec = registry.get("file_search")
    assert spec is not None

    # Requested tool and arguments: model data, carried in a closed envelope
    # with no authority fields available to it.
    assert set(RawToolCall.model_fields) == {"tool", "arguments"}
    assert RawToolCall.model_config["extra"] == "forbid"

    # Tool existence: the registry, and nothing else, resolves a name.
    assert registry.get("shell") is None

    # Grants and budget: RunContext, frozen.
    context = RunContext(run_id="r")
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.max_attempts = 99  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.authorized_tools = frozenset({"shell"})  # type: ignore[misc]

    # Retry eligibility: the controller's own code table plus the capability.
    assert "POLICY_DENIED" not in RETRYABLE_CODES
    assert spec.re_executable is True

    # Side-effect classification and executor: the immutable ToolSpec.
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.side_effect = SideEffect.NONE  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.executor = FakeFileSearchExecutor()  # type: ignore[misc]

    # Execution identity: derived by the controller from its own state.
    assert derive_execution_id("r", "s", 1, "file_search", {}) == derive_execution_id(
        "r", "s", 1, "file_search", {}
    )

    # Recovery decision is operator *input*; recovery authority is the
    # controller's. The decision type cannot express an execution.
    assert "tool" not in OperatorDecision.model_fields
    assert "arguments" not in OperatorDecision.model_fields

    # Terminality: the transition table, which has no edge out of TERMINAL.
    assert TRANSITIONS[State.TERMINAL] == frozenset()

    # And a capability cannot be added to a live registry.
    with pytest.raises(AttributeError):
        registry._by_name = {}
    assert isinstance(registry, ToolRegistry)
    assert isinstance(spec, ToolSpec)


def test_the_authority_matrix_check_is_not_vacuous() -> None:
    """Adversarial control: an unfrozen stand-in must fail the same assertions."""
    import dataclasses

    @dataclasses.dataclass
    class MutableContext:
        max_attempts: int = 3

    loose = MutableContext()
    loose.max_attempts = 99  # no exception — which is why the real one is frozen
    assert loose.max_attempts == 99


def test_state_is_importable_for_the_matrix() -> None:
    """Guards the import the matrix test relies on, so a rename fails loudly."""
    from local_agent.state_machine import State as _State

    assert _State.TERMINAL.value == "TERMINAL"
