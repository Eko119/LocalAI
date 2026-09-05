"""The HTTP transport — the only production module permitted network access.

`tests/test_architecture.py` enforces that: the controller, policy, state
machine, contracts, registry, wiring, executors, the model adapter, and the
transport seam all still fail the build if they acquire a network import. The
grant is per module, exactly as the filesystem grant was in Milestone 2, and
never by widening the global allowlist.

**No new dependency.** This uses `urllib.request` from the standard library.
The behaviour it relies on was verified empirically rather than assumed: a
POST with a JSON body and a Bearer header, an explicit `timeout=` that raises
`TimeoutError`, a `read(n)` that stops after n bytes on an arbitrarily large
body, `urllib.error.HTTPError` on a non-2xx status, and `urllib.error.URLError`
when the host refuses the connection.

**No retries here.** The controller owns retry policy. A transport that
retried three times inside a controller that retries three times would
silently make nine model calls against a budget of three. Every attempt this
module makes is one attempt the controller asked for and can see.
"""

from __future__ import annotations

import asyncio
import urllib.error
import urllib.request

from ..model_adapter import ModelResponseInvalid, ModelTransportError, ModelTransportTimeout
from ..model_config import ModelServiceConfig
from ..model_transport import TransportRequest, TransportResponse


class HttpModelTransport:
    """Speaks to the configured model service over HTTP.

    Everything that could vary — where the service lives, how long to wait,
    how much to read, whether to authenticate — comes from a frozen
    `ModelServiceConfig` supplied by trusted wiring at construction. Nothing
    is derived from a request, and therefore nothing from model output.
    """

    def __init__(self, config: ModelServiceConfig) -> None:
        self._config = config

    async def send(self, request: TransportRequest) -> TransportResponse:
        """Perform one bounded round trip, off the event loop."""
        # `urllib` is blocking. Running it on a worker thread keeps the
        # controller's event loop responsive without adding an async HTTP
        # dependency for a single request per attempt.
        return await asyncio.to_thread(self._send_blocking, request)

    def _send_blocking(self, request: TransportRequest) -> TransportResponse:
        config = self._config
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if config.api_key is not None:
            # The credential is applied here and nowhere else. It is not part
            # of `TransportRequest`, so it never reaches the adapter, the
            # scripted transport's recording, or an audit event.
            headers["Authorization"] = f"Bearer {config.api_key}"

        # The scheme is constrained to http/https by ModelServiceConfig, so this
        # cannot be turned into a file:, ftp:, or data: fetch by configuration.
        http_request = urllib.request.Request(
            url=f"{config.base_url}{request.path}",
            data=request.body,
            headers=headers,
            method="POST",
        )

        ceiling = config.max_response_bytes
        try:
            with urllib.request.urlopen(http_request, timeout=config.timeout_seconds) as response:
                # Read one byte past the ceiling: enough to prove the body is
                # oversized, never enough to hold an oversized body.
                body = response.read(ceiling + 1)
                status = int(response.status)
        except TimeoutError as exc:
            # Neither the URL nor the socket error text is forwarded.
            raise ModelTransportTimeout("model_transport_timeout") from exc
        except urllib.error.HTTPError as exc:
            # A non-2xx status. The body may carry an upstream error message
            # that could name internal hosts, so it is read and discarded
            # rather than propagated.
            raise ModelTransportError(f"model_service_status_{exc.code}") from exc
        except urllib.error.URLError as exc:
            # DNS failure, connection refused, TLS failure. `exc.reason` can
            # contain the host, so it is deliberately not included.
            raise ModelTransportError("model_transport_unreachable") from exc
        except OSError as exc:
            raise ModelTransportError("model_transport_failed") from exc

        if len(body) > ceiling:
            raise ModelResponseInvalid("model_response_too_large")

        return TransportResponse(status=status, body=body)
