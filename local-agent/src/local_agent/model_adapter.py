"""The model boundary.

The controller depends on this Protocol and nothing else about the model.
There is no import of, or reference to, Gemma, llama.cpp, an HTTP client, or
any vendor SDK anywhere in this package — swapping in a real runtime later is
an additive change behind `ModelAdapter`, not a controller change.

`ScriptedModelAdapter` is the deterministic fake used by the tests. It can
emit anything a hostile model could: malformed JSON, tool calls hidden in
reasoning, unknown tool names, smuggled budget fields, or the same invalid
proposal forever.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .contracts import ModelRequest, ModelResponse


class ModelAdapterError(RuntimeError):
    """Base for expected, normalized failures of the model boundary.

    These mirror the executor exceptions in `registry.py`: the controller
    catches them and turns each into one of the eight existing
    `ControllerError` codes. No new code was added to that protocol.

    `reason` is a controller-private slug for the audit stream. It must never
    carry a URL, a host, a header, a credential, or an upstream exception
    message; the exception's own message is never forwarded to the model.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ModelTransportTimeout(ModelAdapterError):
    """The model service did not answer within the configured timeout.

    Normalized to `EXECUTION_TIMEOUT` — retryable, and bounded by the
    controller's existing attempt budget. The adapter never retries on its
    own; see `docs/milestone-3-decisions.md` on why a transport-level retry
    would silently multiply the controller's budget.
    """


class ModelTransportError(ModelAdapterError):
    """The model service could not be reached, or answered with an error status.

    Normalized to `EXECUTION_FAILED` — retryable and bounded.
    """


class ModelResponseInvalid(ModelAdapterError):
    """The model service answered, but the answer was not usable.

    Malformed JSON, a body that violates the response schema, an oversized
    body, or an oversized structured output. Normalized to
    `VERIFICATION_FAILED` — the same code the controller already uses when a
    tool result fails its declared schema, for the same reason: something
    downstream returned a shape we cannot trust.
    """


@runtime_checkable
class ModelAdapter(Protocol):
    """Narrow interface: text in, untrusted candidate text out."""

    async def chat(self, request: ModelRequest) -> ModelResponse: ...


@dataclass
class ScriptedModelAdapter:
    """Deterministic fake model.

    Returns `responses` in order. Once exhausted it repeats the final entry,
    which is what makes "the model keeps proposing the same invalid call"
    natural to script without the test having to know how many attempts the
    controller will make.

    `requests` records everything the controller sent, so tests can assert on
    the sanitized feedback the model was given and prove no fourth attempt
    was ever requested.
    """

    responses: tuple[ModelResponse, ...]
    requests: list[ModelRequest] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.responses:
            raise ValueError("ScriptedModelAdapter requires at least one response")

    @property
    def call_count(self) -> int:
        return len(self.requests)

    async def chat(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        index = min(len(self.requests) - 1, len(self.responses) - 1)
        return self.responses[index]
