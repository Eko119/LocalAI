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
