"""Tests for the real HTTP transport — the module holding the network grant.

Everything else in the suite drives a `ScriptedTransport`, which by design
never executes a line of `transports/http.py`. That would leave the one module
allowed to open a socket entirely unverified, so these tests exercise it
against a standard-library HTTP server bound to loopback.

This is not a live-model test: no LocalAI server, no credentials, no network
beyond `127.0.0.1`, and nothing downloaded. It runs in ordinary offline CI.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import threading
import time
from collections.abc import Iterator

import pytest
from conftest import model_config

from local_agent.model_adapter import (
    ModelResponseInvalid,
    ModelTransportError,
    ModelTransportTimeout,
)
from local_agent.model_transport import TransportRequest
from local_agent.transports.http import HttpModelTransport

SENTINEL = "sk-transport-sentinel-9911"


# Server-side request counter. It is what makes "the client does not retry"
# a measured fact rather than an assumption about urllib's internals.
REQUEST_COUNTS: dict[str, int] = {}


class _Handler(http.server.BaseHTTPRequestHandler):
    """Echoes the request back, or misbehaves in a scripted way."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        REQUEST_COUNTS[self.path] = REQUEST_COUNTS.get(self.path, 0) + 1

        for status_path, code in (("/401", 401), ("/404", 404), ("/503", 503)):
            if self.path.endswith(status_path):
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

        if self.path.endswith("/slow"):
            time.sleep(5)
        if self.path.endswith("/error"):
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'{"error":"upstream detail with /internal/path"}')
            return
        if self.path.endswith("/huge"):
            payload = b'{"pad":"' + b"x" * 300_000 + b'"}'
        else:
            payload = json.dumps(
                {
                    "echo": body.decode("utf-8"),
                    "authorization": self.headers.get("Authorization"),
                    "content_type": self.headers.get("Content-Type"),
                }
            ).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:
        """Silence the default stderr access log."""


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


def send(base_url: str, path: str, **overrides: object) -> object:
    config = model_config(base_url=base_url, **overrides)
    transport = HttpModelTransport(config)
    return asyncio.run(transport.send(TransportRequest(path=path, body=b'{"model":"m"}')))


def test_a_successful_round_trip_returns_status_and_body(server: str) -> None:
    response = send(server, "/v1/chat/completions")
    assert response.status == 200  # type: ignore[attr-defined]
    echoed = json.loads(response.body)  # type: ignore[attr-defined]
    assert json.loads(echoed["echo"]) == {"model": "m"}
    assert echoed["content_type"] == "application/json"


def test_the_credential_is_sent_as_a_bearer_header(server: str) -> None:
    response = send(server, "/v1/chat/completions", api_key=SENTINEL)
    echoed = json.loads(response.body)  # type: ignore[attr-defined]
    assert echoed["authorization"] == f"Bearer {SENTINEL}"


def test_no_authorization_header_is_sent_when_no_key_is_configured(server: str) -> None:
    response = send(server, "/v1/chat/completions", api_key=None)
    echoed = json.loads(response.body)  # type: ignore[attr-defined]
    assert echoed["authorization"] is None


def test_an_oversized_body_is_refused_without_being_held(server: str) -> None:
    """The read stops one byte past the ceiling, whatever the real size is."""
    with pytest.raises(ModelResponseInvalid) as excinfo:
        send(server, "/huge", max_response_bytes=1024, max_structured_output_bytes=512)
    assert excinfo.value.reason == "model_response_too_large"


def test_a_body_at_the_ceiling_is_accepted(server: str) -> None:
    response = send(server, "/v1/chat/completions", max_response_bytes=1_000_000)
    assert response.status == 200  # type: ignore[attr-defined]


def test_a_server_error_becomes_a_normalized_transport_error(server: str) -> None:
    with pytest.raises(ModelTransportError) as excinfo:
        send(server, "/error")
    assert excinfo.value.reason == "model_service_status_500"
    # The upstream body named an internal path; none of it is carried.
    assert "/internal/path" not in str(excinfo.value)


def test_a_hanging_server_becomes_a_normalized_timeout(server: str) -> None:
    """No HTTP operation may be unbounded."""
    started = time.monotonic()
    with pytest.raises(ModelTransportTimeout) as excinfo:
        send(server, "/slow", timeout_seconds=0.3)
    elapsed = time.monotonic() - started

    assert excinfo.value.reason == "model_transport_timeout"
    assert elapsed < 4.0, "the configured timeout did not bound the call"


def test_a_refused_connection_becomes_a_normalized_transport_error() -> None:
    # Port 1 on loopback: nothing listens there.
    with pytest.raises(ModelTransportError) as excinfo:
        send("http://127.0.0.1:1", "/v1/chat/completions", timeout_seconds=2.0)
    assert excinfo.value.reason == "model_transport_unreachable"


def test_transport_failures_never_carry_the_host_or_the_credential() -> None:
    with pytest.raises(ModelTransportError) as excinfo:
        send("http://127.0.0.1:1", "/v1/chat/completions", timeout_seconds=2.0, api_key=SENTINEL)

    rendered = f"{excinfo.value!r} {excinfo.value.reason}"
    assert SENTINEL not in rendered
    assert "127.0.0.1" not in rendered
    assert "Bearer" not in rendered


# ===========================================================================
# Milestone 4: the client must not retry, and status codes must normalize
# ===========================================================================


@pytest.mark.parametrize(
    ("path", "code"), [("/401", 401), ("/404", 404), ("/error", 500), ("/503", 503)]
)
def test_error_statuses_normalize_and_are_not_retried(server: str, path: str, code: int) -> None:
    """One controller attempt must produce exactly one HTTP request.

    A client that quietly retried would multiply the controller's budget
    without the controller ever knowing. This counts requests on the *server*
    side, so it measures what actually happened on the wire.
    """
    REQUEST_COUNTS.clear()

    with pytest.raises(ModelTransportError) as excinfo:
        send(server, path)

    assert excinfo.value.reason == f"model_service_status_{code}"
    assert REQUEST_COUNTS.get(path) == 1, "the HTTP client retried on its own"


def test_a_timeout_is_not_retried(server: str) -> None:
    REQUEST_COUNTS.clear()

    with pytest.raises(ModelTransportTimeout):
        send(server, "/slow", timeout_seconds=0.3)

    assert REQUEST_COUNTS.get("/slow") == 1


def test_controller_attempts_equal_wire_requests_over_a_real_socket(server: str) -> None:
    """End-to-end proof over HTTP: three attempts, three requests, no more.

    Everything here is production code except the server: the real controller,
    the real adapter, and the real transport against a real socket.
    """
    import asyncio

    from local_agent.controller import Controller
    from local_agent.model_service import LocalAIModelAdapter
    from local_agent.policy import RunContext
    from local_agent.transports.http import HttpModelTransport
    from local_agent.wiring import build_default_registry, describe_tools

    REQUEST_COUNTS.clear()
    config = model_config(base_url=server)
    registry = build_default_registry()
    adapter = LocalAIModelAdapter(
        transport=HttpModelTransport(config), config=config, tools=describe_tools(registry)
    )

    # The echo endpoint returns a body that is not a chat completion, so every
    # attempt fails verification and the controller spends its whole budget.
    outcome = asyncio.run(
        Controller(registry, adapter).run(
            RunContext(run_id="wire"), [{"role": "user", "content": "hello"}]
        )
    )

    assert outcome.terminal.code == "RETRY_EXHAUSTED"
    assert outcome.attempts == 3
    assert REQUEST_COUNTS.get("/v1/chat/completions") == 3


def test_a_failing_status_does_not_trigger_endpoint_discovery(server: str) -> None:
    """A 404 must not make the client go looking for another path."""
    REQUEST_COUNTS.clear()

    with pytest.raises(ModelTransportError):
        send(server, "/404")

    assert set(REQUEST_COUNTS) == {"/404"}, "the client probed additional endpoints"
