"""Trusted configuration for the model service (Milestone 3).

Everything here is operator authority. The model never supplies a base URL,
a host, a port, an endpoint, a credential, a timeout, or a ceiling — it can
only propose a tool call through the existing structured channel. There is no
code path by which model output reaches this module.

**Why the URL is validated by hand rather than with `urllib.parse`.** Keeping
`urllib` confined to exactly one module (`transports/http.py`) makes the
network capability grant a one-line fact the architecture test can assert.
Importing `urllib.parse` here for string work would blur that, and the
validation this boundary actually needs is a strict whitelist grammar rather
than a permissive parse: over-rejecting an exotic-but-valid URL is harmless
(an operator fixes their config), while under-rejecting one is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# The OpenAI-compatible chat endpoint LocalAI serves. See
# core/http/auth/features.go in the parent repository, which registers
# POST /v1/chat/completions.
CHAT_COMPLETIONS_PATH = "/v1/chat/completions"

ALLOWED_SCHEMES = frozenset({"http", "https"})


def _validate_base_url(value: str) -> str:
    """Accept only `http(s)://host[:port][/path]`, with no credentials.

    Rejected, each for a reason: a missing or unsupported scheme (this is not
    a general-purpose fetcher — no `file:`, `ftp:`, `data:`, or `gopher:`);
    credentials in the authority (`http://user:pass@host`), which would put a
    secret in every log line that echoed the URL; an empty host; whitespace,
    which is how header-injection payloads usually arrive; and a query or
    fragment, which the chat endpoint has no use for.
    """
    if not value:
        raise ValueError("base_url must not be empty")
    if any(character.isspace() for character in value):
        raise ValueError("base_url must not contain whitespace")
    if "?" in value or "#" in value:
        raise ValueError("base_url must not contain a query or fragment")

    scheme, separator, remainder = value.partition("://")
    if not separator:
        raise ValueError("base_url must include a scheme, e.g. http://host:port")
    if scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(f"unsupported URL scheme: {scheme!r}")
    if not remainder:
        raise ValueError("base_url must include a host")

    authority, slash, path = remainder.partition("/")
    if "@" in authority:
        raise ValueError("base_url must not embed credentials")
    if not authority:
        raise ValueError("base_url must include a host")

    host, colon, port = authority.rpartition(":")
    if not colon:
        host, port = authority, ""
    if not host:
        raise ValueError("base_url must include a host")
    if port:
        if not port.isdigit():
            raise ValueError("base_url port must be numeric")
        if not 1 <= int(port) <= 65535:
            raise ValueError("base_url port must be between 1 and 65535")

    # Normalize away a trailing slash so joining a path is unambiguous.
    normalized = f"{scheme.lower()}://{authority}"
    if slash and path:
        normalized = f"{normalized}/{path.rstrip('/')}"
    return normalized


@dataclass(frozen=True)
class ModelServiceConfig:
    """Immutable, validated connection and budget settings for the model service.

    Frozen for the same reason `RunContext` is: every field is authority. The
    model cannot widen a ceiling, lengthen a timeout, or redirect a request,
    and an attempt to mutate one raises at the point of attempt.

    `api_key` is declared `repr=False`. That is not cosmetic: a frozen
    dataclass's generated `__repr__` would otherwise print the credential into
    any log line, exception, or debugger frame that happened to render the
    config. A regression test supplies a sentinel key and asserts it appears
    in neither `repr()` nor `str()`.
    """

    base_url: str
    model: str
    api_key: str | None = field(default=None, repr=False)
    # Model inference is not tool execution: this bounds one HTTP round trip
    # to the model service and is deliberately separate from
    # `ToolSpec.timeout_seconds`, which bounds a tool call.
    timeout_seconds: float = 30.0
    max_response_bytes: int = 1_048_576  # 1 MiB
    max_structured_output_bytes: int = 65_536  # 64 KiB
    temperature: float = 0.0
    max_tokens: int = 1_024

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", _validate_base_url(self.base_url))

        if not self.model:
            raise ValueError("model must not be empty")
        if any(character.isspace() for character in self.model):
            raise ValueError("model must not contain whitespace")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if self.max_response_bytes < 1:
            raise ValueError("max_response_bytes must be >= 1")
        if self.max_structured_output_bytes < 1:
            raise ValueError("max_structured_output_bytes must be >= 1")
        if self.max_structured_output_bytes > self.max_response_bytes:
            raise ValueError("max_structured_output_bytes must not exceed max_response_bytes")
        if self.temperature < 0:
            raise ValueError("temperature must be >= 0")
        if self.max_tokens < 1:
            raise ValueError("max_tokens must be >= 1")
        if self.api_key is not None and not self.api_key:
            raise ValueError("api_key must be None or a non-empty string")

    @property
    def chat_completions_url(self) -> str:
        return f"{self.base_url}{CHAT_COMPLETIONS_PATH}"
