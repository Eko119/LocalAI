"""Support for the opt-in live LocalAI integration tests (Milestone 4).

Two rules shape this module.

**The gate decides skip versus fail, and the distinction is mandatory.**

    gate absent                  -> SKIP  (deterministic CI, LocalAI offline)
    gate present, misconfigured  -> FAIL  (the operator asked for a live run)
    gate present, unreachable    -> FAIL  (same reason)

Turning an explicitly requested live test into a silent skip is the failure
mode this module exists to prevent: an operator who sets the gate and sees
green must be able to conclude the live path actually worked.

**Configuration is read here, not in the package.** `src/local_agent/` reads
no environment variable anywhere — trusted wiring constructs config
explicitly, and ambient configuration is a deployment concern. Reading env
here also keeps `os` out of the production import allowlist, which the
architecture tests enforce.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import pytest

from local_agent.model_config import ModelServiceConfig

# The opt-in gate. Established in Milestone 3; reused unchanged.
LIVE_GATE = "LOCAL_AGENT_LIVE_MODEL"

# LocalAI's own configuration conventions, reused rather than reinvented:
#   core/cli/run.go — APIKeys reads `LOCALAI_API_KEY,API_KEY`
#                     Address reads `LOCALAI_ADDRESS,ADDRESS`, default ":8080"
# `LOCALAI_BASE_URL` is this project's own addition, because LOCALAI_ADDRESS
# is a *bind* address (":8080") rather than a URL a client can dial.
BASE_URL_VAR = "LOCALAI_BASE_URL"
ADDRESS_VAR = "LOCALAI_ADDRESS"
MODEL_VAR = "LOCALAI_MODEL"
API_KEY_VARS = ("LOCALAI_API_KEY", "API_KEY")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = "8080"


class LiveConfigurationError(Exception):
    """The live gate is on but the environment does not describe a service.

    Deliberately not a `Skipped`: the operator asked for a live run, so an
    incomplete configuration is a failure they need to see and fix.
    """


@dataclass(frozen=True)
class LiveSettings:
    """Everything a live test needs, with the credential kept out of `repr`."""

    config: ModelServiceConfig
    model: str

    @property
    def endpoint_shape(self) -> str:
        """The endpoint in a form safe to print: scheme and host only.

        Never includes a credential, because `ModelServiceConfig` rejects a
        URL that embeds one, and never includes a path beyond the host.
        """
        scheme, _, remainder = self.config.base_url.partition("://")
        authority = remainder.split("/", 1)[0]
        return f"{scheme}://{authority}"


def live_enabled() -> bool:
    return bool(os.environ.get(LIVE_GATE))


def _base_url_from_environment() -> str:
    """Prefer an explicit client URL; otherwise derive one from LOCALAI_ADDRESS.

    `LOCALAI_ADDRESS` is a bind address, so ":8080" means "all interfaces,
    port 8080" to the server and has to become a dialable host for a client.
    An empty host is resolved to loopback rather than guessed at.
    """
    explicit = os.environ.get(BASE_URL_VAR)
    if explicit:
        return explicit

    address = os.environ.get(ADDRESS_VAR, f":{DEFAULT_PORT}")
    host, _, port = address.rpartition(":")
    if not port.isdigit():
        host, port = address, DEFAULT_PORT
    return f"http://{host or DEFAULT_HOST}:{port or DEFAULT_PORT}"


def _api_key_from_environment() -> str | None:
    """LocalAI's own precedence: LOCALAI_API_KEY, then API_KEY."""
    for variable in API_KEY_VARS:
        value = os.environ.get(variable)
        if value:
            return value
    return None


def live_settings() -> LiveSettings:
    """Build live settings from the environment, or raise a clear failure.

    Raises `LiveConfigurationError` rather than skipping, and its message
    names the missing variable without ever quoting a credential.
    """
    model = os.environ.get(MODEL_VAR)
    if not model:
        raise LiveConfigurationError(
            f"{LIVE_GATE} is set, so a live run was requested, but {MODEL_VAR} is not set. "
            f"Set {MODEL_VAR} to a model the configured LocalAI instance serves. "
            f"Optionally set {BASE_URL_VAR} (or {ADDRESS_VAR}) and "
            f"{API_KEY_VARS[0]}/{API_KEY_VARS[1]}."
        )

    try:
        config = ModelServiceConfig(
            base_url=_base_url_from_environment(),
            model=model,
            api_key=_api_key_from_environment(),
            # A live model is slower than a fixture: bounded generously enough
            # to answer, tightly enough to fail rather than hang.
            timeout_seconds=60.0,
            max_tokens=256,
        )
    except ValueError as exc:
        # The message can name the offending setting but never its value.
        raise LiveConfigurationError(
            f"{LIVE_GATE} is set but the resulting configuration is invalid: {exc}"
        ) from exc

    return LiveSettings(config=config, model=model)


def require_live() -> LiveSettings:
    """Skip when the gate is absent; fail loudly when it is present but broken."""
    if not live_enabled():
        pytest.skip(f"live LocalAI integration test: set {LIVE_GATE}=1 and {MODEL_VAR} to enable")
    try:
        return live_settings()
    except LiveConfigurationError as exc:
        message = str(exc)
    # Failing outside the handler keeps the operator's message on its own,
    # rather than chained behind "another exception occurred".
    pytest.fail(message, pytrace=False)


@dataclass
class LiveDiagnostic:
    """Sanitized structural record of a live exchange.

    Records shape, never content: which channel carried something, how many
    tool calls arrived, the normalized error if any, and the controller's
    state trace. It deliberately cannot hold model text, a credential, a
    physical path, or a URL, so it is safe to print from a live run.
    """

    endpoint_shape: str
    model: str
    request_accepted: bool = False
    response_accepted: bool = False
    had_reasoning: bool = False
    had_narrative: bool = False
    had_structured_output: bool = False
    structured_output_parsed: bool | None = None
    proposed_tool: str | None = None
    normalized_error: str | None = None
    state_trace: tuple[str, ...] = ()
    transport_calls: int = 0

    def render(self) -> str:
        """One line per fact, safe to emit from a live test run."""
        return "\n".join(
            f"  {name}: {value}"
            for name, value in (
                ("endpoint", self.endpoint_shape),
                ("model", self.model),
                ("request_accepted", self.request_accepted),
                ("response_accepted", self.response_accepted),
                ("had_reasoning", self.had_reasoning),
                ("had_narrative", self.had_narrative),
                ("had_structured_output", self.had_structured_output),
                ("structured_output_parsed", self.structured_output_parsed),
                ("proposed_tool", self.proposed_tool),
                ("normalized_error", self.normalized_error),
                ("transport_calls", self.transport_calls),
                ("state_trace", " -> ".join(self.state_trace)),
            )
        )
