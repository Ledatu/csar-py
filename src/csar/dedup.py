from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

Handler = Callable[[httpx.Request], Awaitable[httpx.Response]]

_REPLAYED_EXTENSIONS = ("http_version", "reason_phrase")


class _LeaderCancelled(Exception):
    pass


@dataclass(frozen=True)
class _Snapshot:
    status_code: int
    headers: list[tuple[bytes, bytes]]
    body: bytes
    extensions: dict[str, Any] = field(default_factory=dict)

    def response(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            self.status_code,
            headers=self.headers,
            stream=httpx.ByteStream(self.body),
            request=request,
            extensions=dict(self.extensions),
        )


async def _snapshot(response: httpx.Response) -> _Snapshot:
    stream = response.stream
    try:
        if not isinstance(stream, httpx.AsyncByteStream):
            raise TypeError("dedup needs an async response stream")
        body = b"".join([chunk async for chunk in stream])
    finally:
        await response.aclose()
    extensions = {k: v for k, v in response.extensions.items() if k in _REPLAYED_EXTENSIONS}
    return _Snapshot(response.status_code, list(response.headers.raw), body, extensions)


class RequestDeduplicator:
    """Collapses identical in-flight GET requests into one upstream call."""

    def __init__(self) -> None:
        self._inflight: dict[str, asyncio.Future[_Snapshot]] = {}

    @property
    def size(self) -> int:
        return len(self._inflight)

    @staticmethod
    def key(request: httpx.Request) -> str | None:
        if request.method != "GET":
            return None
        url = request.url
        query = str(httpx.QueryParams(sorted(url.params.multi_items())))
        credential = request.headers.get("authorization")
        owner = hashlib.sha256(credential.encode()).hexdigest()[:16] if credential else ""
        return f"GET {url.scheme}://{url.netloc.decode('ascii')}{url.path}?{query}#{owner}"

    async def execute(self, request: httpx.Request, send: Handler) -> httpx.Response:
        key = self.key(request)
        if key is None:
            return await send(request)
        pending = self._inflight.get(key)
        if pending is not None:
            try:
                snapshot = await asyncio.shield(pending)
            except _LeaderCancelled:
                return await self.execute(request, send)
            return snapshot.response(request)

        future: asyncio.Future[_Snapshot] = asyncio.get_running_loop().create_future()
        self._inflight[key] = future
        try:
            snapshot = await _snapshot(await send(request))
        except asyncio.CancelledError:
            future.set_exception(_LeaderCancelled())
            future.exception()
            raise
        except BaseException as exc:
            future.set_exception(exc)
            future.exception()
            raise
        else:
            future.set_result(snapshot)
        finally:
            self._inflight.pop(key, None)
        return snapshot.response(request)
