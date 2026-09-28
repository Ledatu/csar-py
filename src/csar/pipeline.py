from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Awaitable, Callable, Sequence

import httpx

from .auth import TokenSource
from .circuit_breaker import ClientCircuitBreaker, origin_of
from .constants import (
    BACKPRESSURE_STATUS,
    CIRCUIT_STATUSES,
    HEADER_AUTHORIZATION,
    HEADER_CLIENT_LIMIT,
    HEADER_REQUEST_ID,
    HEADER_TRACEPARENT,
    HEADER_WAIT_MS,
    LEGACY_CIRCUIT_BODY_MARKER,
    PROTOCOL_VERSION,
    RETRYABLE_STATUSES,
)
from .dedup import RequestDeduplicator
from .errors import CsarBackpressureError, CsarCircuitBrokenError
from .extract import csar_status, parse_api_error, protocol_version, wait_time
from .trace import generate_traceparent

logger = logging.getLogger("csar")

Handler = Callable[[httpx.Request], Awaitable[httpx.Response]]
Middleware = Callable[[httpx.Request, Handler], Awaitable[httpx.Response]]
RetryHook = Callable[[float, int, httpx.Response], None]
Sleep = Callable[[float], Awaitable[None]]


class PipelineTransport(httpx.AsyncBaseTransport):
    """Runs middlewares left to right (the first is outermost) around an inner transport."""

    def __init__(self, middlewares: Sequence[Middleware], inner: httpx.AsyncBaseTransport) -> None:
        self._middlewares = tuple(middlewares)
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._dispatch(0, request)

    async def _dispatch(self, index: int, request: httpx.Request) -> httpx.Response:
        if index == len(self._middlewares):
            return await self._inner.handle_async_request(request)
        return await self._middlewares[index](
            request, functools.partial(self._dispatch, index + 1)
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


def auth_middleware(tokens: TokenSource) -> Middleware:
    async def middleware(request: httpx.Request, call_next: Handler) -> httpx.Response:
        await request.aread()
        request.headers[HEADER_AUTHORIZATION] = f"Bearer {await tokens.get_token()}"
        response = await call_next(request)
        if response.status_code != 401:
            return response
        logger.debug("csar: 401 from %s, refreshing the STS token and retrying once", request.url)
        await response.aclose()
        tokens.clear()
        request.headers[HEADER_AUTHORIZATION] = f"Bearer {await tokens.get_token()}"
        return await call_next(request)

    return middleware


def headers_middleware(
    *, client_limit_rps: float | None = None, generate_trace_id: bool = False
) -> Middleware:
    async def middleware(request: httpx.Request, call_next: Handler) -> httpx.Response:
        if client_limit_rps is not None:
            request.headers[HEADER_CLIENT_LIMIT] = f"{client_limit_rps:g}"
        if generate_trace_id:
            trace_id, traceparent = generate_traceparent()
            request.headers.setdefault(HEADER_REQUEST_ID, trace_id)
            request.headers.setdefault(HEADER_TRACEPARENT, traceparent)
        return await call_next(request)

    return middleware


def circuit_breaker_middleware(breaker: ClientCircuitBreaker) -> Middleware:
    async def middleware(request: httpx.Request, call_next: Handler) -> httpx.Response:
        origin = origin_of(request.url)
        breaker.check(origin)
        response = await call_next(request)
        if response.status_code >= 500:
            breaker.on_failure(origin)
            logger.warning("csar: circuit breaker %s for %s", breaker.state(origin), origin)
        else:
            breaker.on_success(origin)
        return response

    return middleware


def dedup_middleware(dedup: RequestDeduplicator) -> Middleware:
    async def middleware(request: httpx.Request, call_next: Handler) -> httpx.Response:
        return await dedup.execute(request, call_next)

    return middleware


def retry_middleware(
    *,
    max_wait: float,
    max_retries: int,
    on_retry: RetryHook | None = None,
    sleep: Sleep = asyncio.sleep,
) -> Middleware:
    async def middleware(request: httpx.Request, call_next: Handler) -> httpx.Response:
        await request.aread()
        attempt = 0
        while True:
            response = await call_next(request)
            _check_protocol(response)
            if response.status_code != BACKPRESSURE_STATUS:
                _log_server_wait(response, request)
                return response

            status = csar_status(response.headers)
            body = await response.aread()
            if status in CIRCUIT_STATUSES or (
                status is None and LEGACY_CIRCUIT_BODY_MARKER in body
            ):
                await response.aclose()
                raise CsarCircuitBrokenError(
                    f"server circuit breaker is {status or 'open'} for {request.url}",
                    source="server",
                    retry_after=wait_time(response.headers)[0],
                )
            if status not in RETRYABLE_STATUSES:
                return response

            attempt += 1
            wait, source = wait_time(response.headers)
            if wait is None:
                api_error = parse_api_error(response.status_code, body)
                if api_error is not None and api_error.retry_after is not None:
                    wait, source = api_error.retry_after, "retry_after_ms"
            await response.aclose()

            if wait is not None and wait > max_wait:
                raise CsarBackpressureError(
                    f"router requested {wait:.3f}s wait, exceeds max_wait ({max_wait}s)",
                    requested_wait=wait,
                    attempt=attempt,
                )
            if attempt > max_retries:
                raise CsarBackpressureError(
                    f"max retries ({max_retries}) exhausted for {request.url}",
                    requested_wait=wait,
                    attempt=attempt,
                )
            delay = wait if wait is not None else 1.0
            logger.info(
                "csar: %s, waiting %.3fs (from %s), attempt %d/%d for %s",
                status, delay, source, attempt, max_retries, request.url,
            )
            if on_retry is not None:
                on_retry(delay, attempt, response)
            await sleep(delay)

    return middleware


def _check_protocol(response: httpx.Response) -> None:
    version = protocol_version(response.headers)
    if version is not None and version > PROTOCOL_VERSION:
        logger.warning(
            "csar: router speaks protocol v%d, this SDK implements v%d", version, PROTOCOL_VERSION
        )


def _log_server_wait(response: httpx.Response, request: httpx.Request) -> None:
    waited = response.headers.get(HEADER_WAIT_MS)
    if waited is not None:
        logger.debug("csar: router queued %s for %sms before forwarding", request.url, waited)
