"""The transport seam beneath the model adapter (Milestone 3).

    Controller  ->  ModelAdapter  ->  ModelTransport  ->  model service

This module deliberately performs no I/O and imports nothing network-capable.
It defines the shape of a request and a response, and a deterministic scripted
transport for tests. The one implementation that actually opens a socket lives
in `transports/http.py`, which is the sole holder of the network grant.

The seam exists so the deterministic suite never depends on a running LocalAI
server, and so the controller cannot tell — and must not care — whether a
response came from HTTP, a scripted double, or some future provider.

**Credentials never cross this seam.** `TransportRequest` carries a path and a
body and nothing else; the API key lives inside the transport, which injects
the `Authorization` header itself. That is why `ScriptedTransport` can record
every request verbatim and a test can assert the recording contains no secret.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .model_adapter import ModelTransportError


@dataclass(frozen=True)
class TransportRequest:
    """One request to the model service, with no credential and no host.

    `path` is chosen by the adapter from a module constant, never from model
    output. `body` is the serialized JSON payload.
    """

    path: str
    body: bytes


@dataclass(frozen=True)
class TransportResponse:
    """One raw response. The body is bytes; nothing has interpreted it yet."""

    status: int
    body: bytes


@runtime_checkable
class ModelTransport(Protocol):
    """Send one request, get one response, or raise a normalized failure."""

    async def send(self, request: TransportRequest) -> TransportResponse: ...


@dataclass
class ScriptedTransport:
    """Deterministic in-process transport for tests.

    Each entry in `outcomes` is either a `TransportResponse` to return or a
    `ModelAdapterError` instance to raise, so a test can script a timeout, a
    connection failure, a server error, or a malformed body without a socket.
    Once exhausted it repeats the final entry, which is how "the service fails
    forever" is expressed without the test knowing the retry budget.

    `requests` records exactly what the adapter sent. Tests assert on it to
    prove the request carries no credential, no filesystem root, no policy
    ceiling, and no retry-budget field.
    """

    outcomes: tuple[TransportResponse | BaseException, ...]
    requests: list[TransportRequest] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.outcomes:
            raise ValueError("ScriptedTransport requires at least one outcome")

    @property
    def call_count(self) -> int:
        return len(self.requests)

    @property
    def bodies(self) -> list[str]:
        """Every request body decoded as text, for assertion convenience."""
        return [request.body.decode("utf-8") for request in self.requests]

    async def send(self, request: TransportRequest) -> TransportResponse:
        self.requests.append(request)
        outcome = self.outcomes[min(len(self.requests) - 1, len(self.outcomes) - 1)]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class UnreachableTransport:
    """A transport that always fails. Useful for proving nothing depends on it."""

    async def send(self, request: TransportRequest) -> TransportResponse:
        raise ModelTransportError("model_transport_unreachable")
