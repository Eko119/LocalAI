"""Deterministic tests for the live-test boundary itself (Milestone 4).

These run in ordinary offline CI and never contact anything. They exist
because the live tests' *gate* is a security and correctness boundary in its
own right, and the mandatory distinction

    gate absent                 -> SKIP
    gate present, unusable      -> FAIL

is exactly the kind of property that decays silently. If someone later
"tidies" the gate into a blanket skipif, an operator who sets the gate would
see green while nothing ran. The subprocess tests below make that regression
fail the build.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from live_support import (
    LIVE_GATE,
    LiveConfigurationError,
    LiveDiagnostic,
    live_enabled,
    live_settings,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LIVE_MODULE = "tests/test_live_localai.py"

SENTINEL_LIVE_KEY = "sk-live-boundary-sentinel-7731"


def _pytest(
    env_overrides: dict[str, str | None], *arguments: str, timeout: int = 300
) -> subprocess.CompletedProcess[str]:
    """Run pytest in a subprocess with a controlled environment."""
    import os

    env = dict(os.environ)
    for name, value in env_overrides.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value

    return subprocess.run(
        [sys.executable, "-m", "pytest", *arguments, "-q", "-p", "no:cacheprovider", "--no-header"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


# ---------------------------------------------------------------------------
# The mandatory distinction
# ---------------------------------------------------------------------------


def test_without_the_gate_live_tests_skip_and_never_fail() -> None:
    """Deterministic CI must pass with LocalAI entirely offline."""
    result = _pytest({LIVE_GATE: None, "LOCALAI_MODEL": None}, LIVE_MODULE, "-rs")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "skipped" in result.stdout
    assert "failed" not in result.stdout
    # The skip reason must tell the operator how to enable the tests.
    assert LIVE_GATE in result.stdout


def test_with_the_gate_but_no_model_the_live_tests_fail_loudly() -> None:
    """An explicitly requested live run must never degrade into a silent skip."""
    result = _pytest({LIVE_GATE: "1", "LOCALAI_MODEL": None}, LIVE_MODULE)

    assert result.returncode != 0
    assert "failed" in result.stdout
    assert "LOCALAI_MODEL is not set" in result.stdout
    # It must not have been reported as skipped.
    assert " skipped" not in result.stdout.splitlines()[-1]


def test_with_the_gate_and_an_unreachable_service_the_live_tests_fail() -> None:
    """Port 9 (discard) refuses connections: the failure must surface."""
    result = _pytest(
        {
            LIVE_GATE: "1",
            "LOCALAI_MODEL": "any-model",
            "LOCALAI_BASE_URL": "http://127.0.0.1:9",
            "LOCALAI_API_KEY": None,
            "API_KEY": None,
        },
        f"{LIVE_MODULE}::test_live_model_returns_a_mappable_response",
    )

    assert result.returncode != 0
    assert "failed" in result.stdout
    assert "ModelTransportError" in result.stdout or "model_transport_unreachable" in result.stdout


def test_the_deterministic_suite_is_independent_of_localai() -> None:
    """`pytest -m "not live"` passes with no server, no gate, no credentials."""
    result = _pytest(
        {
            LIVE_GATE: None,
            "LOCALAI_MODEL": None,
            "LOCALAI_BASE_URL": None,
            "LOCALAI_API_KEY": None,
        },
        "-m",
        "not live",
        # Skip this module in the child run: it spawns pytest itself, and
        # nesting the recursion would multiply the suite by its own length.
        "--ignore=tests/test_live_boundary.py",
    )

    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
    assert "failed" not in result.stdout
    assert "passed" in result.stdout


# ---------------------------------------------------------------------------
# Environment conventions (task §4)
# ---------------------------------------------------------------------------


def test_the_gate_helper_reads_the_established_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(LIVE_GATE, raising=False)
    assert live_enabled() is False
    monkeypatch.setenv(LIVE_GATE, "1")
    assert live_enabled() is True


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        (":8080", "http://127.0.0.1:8080"),
        ("0.0.0.0:8080", "http://0.0.0.0:8080"),
        ("127.0.0.1:9090", "http://127.0.0.1:9090"),
        ("model-host:1234", "http://model-host:1234"),
    ],
)
def test_localai_address_is_translated_into_a_dialable_url(
    monkeypatch: pytest.MonkeyPatch, address: str, expected: str
) -> None:
    """LOCALAI_ADDRESS is a bind address; a client needs a host to dial."""
    monkeypatch.setenv("LOCALAI_MODEL", "m")
    monkeypatch.delenv("LOCALAI_BASE_URL", raising=False)
    monkeypatch.setenv("LOCALAI_ADDRESS", address)
    assert live_settings().config.base_url == expected


def test_an_explicit_base_url_wins_over_the_bind_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCALAI_MODEL", "m")
    monkeypatch.setenv("LOCALAI_ADDRESS", ":8080")
    monkeypatch.setenv("LOCALAI_BASE_URL", "https://model.internal:8443")
    assert live_settings().config.base_url == "https://model.internal:8443"


def test_the_api_key_follows_localais_own_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    """core/cli/run.go reads `LOCALAI_API_KEY,API_KEY` in that order."""
    monkeypatch.setenv("LOCALAI_MODEL", "m")
    monkeypatch.delenv("LOCALAI_BASE_URL", raising=False)
    monkeypatch.delenv("LOCALAI_ADDRESS", raising=False)

    monkeypatch.delenv("LOCALAI_API_KEY", raising=False)
    monkeypatch.delenv("API_KEY", raising=False)
    assert live_settings().config.api_key is None

    monkeypatch.setenv("API_KEY", "from-api-key")
    assert live_settings().config.api_key == "from-api-key"

    monkeypatch.setenv("LOCALAI_API_KEY", "from-localai-api-key")
    assert live_settings().config.api_key == "from-localai-api-key"


def test_a_missing_model_raises_a_clear_error_naming_no_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LOCALAI_MODEL", raising=False)
    monkeypatch.setenv("LOCALAI_API_KEY", SENTINEL_LIVE_KEY)

    with pytest.raises(LiveConfigurationError) as excinfo:
        live_settings()

    message = str(excinfo.value)
    assert "LOCALAI_MODEL" in message
    assert SENTINEL_LIVE_KEY not in message


def test_an_invalid_endpoint_raises_without_quoting_the_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOCALAI_MODEL", "m")
    monkeypatch.setenv("LOCALAI_BASE_URL", "ftp://not-supported")
    monkeypatch.setenv("LOCALAI_API_KEY", SENTINEL_LIVE_KEY)

    with pytest.raises(LiveConfigurationError) as excinfo:
        live_settings()

    assert SENTINEL_LIVE_KEY not in str(excinfo.value)


# ---------------------------------------------------------------------------
# The sanitized diagnostic (task §14)
# ---------------------------------------------------------------------------


def test_the_diagnostic_records_structure_and_cannot_hold_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOCALAI_MODEL", "test-model")
    monkeypatch.setenv("LOCALAI_BASE_URL", "http://model.internal:8080/base")
    monkeypatch.setenv("LOCALAI_API_KEY", SENTINEL_LIVE_KEY)
    settings = live_settings()

    record = LiveDiagnostic(
        endpoint_shape=settings.endpoint_shape,
        model=settings.model,
        request_accepted=True,
        response_accepted=True,
        had_narrative=True,
        had_structured_output=True,
        structured_output_parsed=True,
        proposed_tool="workspace.list",
        state_trace=("RECEIVE", "CLASSIFY", "GENERATE"),
        transport_calls=1,
    )
    rendered = record.render()

    assert SENTINEL_LIVE_KEY not in rendered
    assert "Bearer" not in rendered
    assert "/base" not in rendered  # endpoint_shape is scheme+authority only
    assert "workspace.list" in rendered
    assert "RECEIVE -> CLASSIFY -> GENERATE" in rendered

    # The record has no field capable of holding model text or a path.
    for field_name in LiveDiagnostic.__dataclass_fields__:
        assert field_name not in {"content", "narrative", "reasoning", "body", "path", "url"}


def test_the_endpoint_shape_never_exposes_a_path_or_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LOCALAI_MODEL", "m")
    monkeypatch.setenv("LOCALAI_BASE_URL", "https://host.internal:8443/deep/path")
    monkeypatch.setenv("LOCALAI_API_KEY", SENTINEL_LIVE_KEY)

    settings = live_settings()
    assert settings.endpoint_shape == "https://host.internal:8443"
    assert SENTINEL_LIVE_KEY not in settings.endpoint_shape
