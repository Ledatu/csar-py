from __future__ import annotations

import asyncio
import gzip

import httpx
import pytest

from csar import CsarTransport, RequestDeduplicator

URL = "https://api.example.test/v1/data"


class GatedHandler:
    def __init__(self, response: httpx.Response | Exception) -> None:
        self._response = response
        self.calls = 0
        self.gate = asyncio.Event()

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        await self.gate.wait()
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def _client(handler: GatedHandler, dedup: RequestDeduplicator | bool = True) -> httpx.AsyncClient:
    transport = CsarTransport(
        httpx.MockTransport(handler), max_wait=1, max_retries=0, dedup=dedup
    )
    return httpx.AsyncClient(transport=transport)


async def _release_after_waiters(handler: GatedHandler) -> None:
    await asyncio.sleep(0.01)
    handler.gate.set()


async def test_collapses_concurrent_identical_gets() -> None:
    body = gzip.compress(b'{"items": [1, 2]}')
    handler = GatedHandler(
        httpx.Response(200, headers={"Content-Encoding": "gzip"}, content=body)
    )
    async with _client(handler) as client:
        results = await asyncio.gather(
            client.get(URL, params={"b": "2", "a": "1"}),
            client.get(URL, params={"a": "1", "b": "2"}),
            client.get(URL, params={"a": "1", "b": "2"}),
            _release_after_waiters(handler),
        )
    responses = results[:3]
    assert handler.calls == 1
    assert [r.json() for r in responses] == [{"items": [1, 2]}] * 3


async def test_does_not_collapse_posts_or_different_credentials() -> None:
    handler = GatedHandler(httpx.Response(200))
    async with _client(handler) as client:
        await asyncio.gather(
            client.post(URL),
            client.post(URL),
            client.get(URL, headers={"Authorization": "Bearer one"}),
            client.get(URL, headers={"Authorization": "Bearer two"}),
            _release_after_waiters(handler),
        )
    assert handler.calls == 4


async def test_errors_reach_every_waiter_and_clear_the_slot() -> None:
    dedup = RequestDeduplicator()
    handler = GatedHandler(httpx.ConnectError("boom"))
    async with _client(handler, dedup) as client:
        results = await asyncio.gather(
            client.get(URL), client.get(URL), _release_after_waiters(handler),
            return_exceptions=True,
        )
    assert [type(r) for r in results[:2]] == [httpx.ConnectError, httpx.ConnectError]
    assert handler.calls == 1
    assert dedup.size == 0


async def test_waiter_takes_over_when_the_leader_is_cancelled() -> None:
    handler = GatedHandler(httpx.Response(200, text="ok"))
    async with _client(handler) as client:
        leader = asyncio.create_task(client.get(URL))
        await asyncio.sleep(0.01)
        follower = asyncio.create_task(client.get(URL))
        await asyncio.sleep(0.01)
        leader.cancel()
        await asyncio.sleep(0.01)
        handler.gate.set()
        response = await follower
        with pytest.raises(asyncio.CancelledError):
            await leader
    assert response.text == "ok"
    assert handler.calls == 2


def test_key_normalises_query_order() -> None:
    a = httpx.Request("GET", URL, params={"x": "1", "y": "2"})
    b = httpx.Request("GET", URL, params={"y": "2", "x": "1"})
    assert RequestDeduplicator.key(a) == RequestDeduplicator.key(b)
    assert RequestDeduplicator.key(httpx.Request("POST", URL)) is None
