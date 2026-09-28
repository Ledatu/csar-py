from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest


class Sleeper:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


@pytest.fixture
def sleeper() -> Sleeper:
    return Sleeper()


class Recorder:
    def __init__(self, responses: list[httpx.Response] | Callable[[httpx.Request], httpx.Response]):
        self._responses = responses
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if callable(self._responses):
            return self._responses(request)
        return self._responses.pop(0)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


def throttled(wait_ms: int | None = None, retry_after: str | None = None) -> httpx.Response:
    headers = {"X-CSAR-Status": "throttled"}
    if wait_ms is not None:
        headers["X-CSAR-Wait-MS"] = str(wait_ms)
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return httpx.Response(
        503,
        headers=headers,
        json={"code": "throttled", "status": 503, "message": "service temporarily unavailable"},
    )
