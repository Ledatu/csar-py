from __future__ import annotations

import asyncio
import ssl
from collections.abc import Sequence
from typing import Any

import httpx

from .auth import TokenSource
from .circuit_breaker import ClientCircuitBreaker
from .dedup import RequestDeduplicator
from .pipeline import (
    Middleware,
    PipelineTransport,
    RetryHook,
    Sleep,
    auth_middleware,
    circuit_breaker_middleware,
    dedup_middleware,
    headers_middleware,
    retry_middleware,
)


class CsarTransport(PipelineTransport):
    """httpx transport speaking the CSAR protocol: auth, headers, breaker, dedup, 503 retry."""

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport | None = None,
        *,
        max_wait: float,
        max_retries: int,
        auth: TokenSource | None = None,
        client_limit_rps: float | None = None,
        circuit_breaker: ClientCircuitBreaker | None = None,
        dedup: RequestDeduplicator | bool = False,
        generate_trace_id: bool = False,
        on_retry: RetryHook | None = None,
        middlewares: Sequence[Middleware] = (),
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        stack: list[Middleware] = []
        if auth is not None:
            stack.append(auth_middleware(auth))
        stack.append(
            headers_middleware(
                client_limit_rps=client_limit_rps, generate_trace_id=generate_trace_id
            )
        )
        stack.extend(middlewares)
        if circuit_breaker is not None:
            stack.append(circuit_breaker_middleware(circuit_breaker))
        if dedup:
            shared = dedup if isinstance(dedup, RequestDeduplicator) else RequestDeduplicator()
            stack.append(dedup_middleware(shared))
        stack.append(
            retry_middleware(
                max_wait=max_wait, max_retries=max_retries, on_retry=on_retry, sleep=sleep
            )
        )
        super().__init__(stack, inner if inner is not None else httpx.AsyncHTTPTransport())


def create_csar_client(
    base_url: str,
    *,
    max_wait: float,
    max_retries: int,
    auth: TokenSource | None = None,
    client_limit_rps: float | None = None,
    circuit_breaker: ClientCircuitBreaker | None = None,
    dedup: RequestDeduplicator | bool = False,
    generate_trace_id: bool = False,
    on_retry: RetryHook | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    verify: ssl.SSLContext | str | bool = True,
    **client_kwargs: Any,
) -> httpx.AsyncClient:
    inner = transport if transport is not None else httpx.AsyncHTTPTransport(verify=verify)
    return httpx.AsyncClient(
        base_url=base_url,
        transport=CsarTransport(
            inner,
            max_wait=max_wait,
            max_retries=max_retries,
            auth=auth,
            client_limit_rps=client_limit_rps,
            circuit_breaker=circuit_breaker,
            dedup=dedup,
            generate_trace_id=generate_trace_id,
            on_retry=on_retry,
        ),
        **client_kwargs,
    )
