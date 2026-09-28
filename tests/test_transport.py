from __future__ import annotations

import json

import httpx
import pytest

from csar import (
    ClientCircuitBreaker,
    CsarBackpressureError,
    CsarCircuitBrokenError,
    CsarTransport,
    PipelineTransport,
    create_csar_client,
)

from .conftest import Recorder, Sleeper, throttled

URL = "https://api.example.test/v1/data"


def _client(recorder: Recorder, sleeper: Sleeper, **kwargs: object) -> httpx.AsyncClient:
    options: dict[str, object] = {"max_wait": 5.0, "max_retries": 3, "sleep": sleeper}
    options.update(kwargs)
    return httpx.AsyncClient(transport=CsarTransport(recorder.transport, **options))  # type: ignore[arg-type]


async def test_passes_non_503_responses_through(sleeper: Sleeper) -> None:
    recorder = Recorder([httpx.Response(429, json={"upstream": True})])
    async with _client(recorder, sleeper) as client:
        response = await client.get(URL)
    assert response.status_code == 429
    assert response.json() == {"upstream": True}
    assert sleeper.calls == []


async def test_retries_throttled_503_using_wait_ms_first(sleeper: Sleeper) -> None:
    recorder = Recorder([throttled(wait_ms=150, retry_after="7"), httpx.Response(200, text="ok")])
    async with _client(recorder, sleeper) as client:
        response = await client.get(URL)
    assert response.text == "ok"
    assert sleeper.calls == [0.15]
    assert len(recorder.requests) == 2


async def test_falls_back_to_retry_after_then_to_body(sleeper: Sleeper) -> None:
    body_only = httpx.Response(
        503,
        headers={"X-CSAR-Status": "backpressure"},
        json={"code": "backpressure", "status": 503, "message": "m", "retry_after_ms": 800},
    )
    recorder = Recorder([throttled(retry_after="2"), body_only, httpx.Response(200)])
    async with _client(recorder, sleeper) as client:
        assert (await client.get(URL)).status_code == 200
    assert sleeper.calls == [2.0, 0.8]


async def test_defaults_to_one_second_without_any_hint(sleeper: Sleeper) -> None:
    recorder = Recorder([throttled(), httpx.Response(200)])
    async with _client(recorder, sleeper) as client:
        assert (await client.get(URL)).status_code == 200
    assert sleeper.calls == [1.0]


async def test_upstream_503_without_csar_status_is_returned(sleeper: Sleeper) -> None:
    recorder = Recorder([httpx.Response(503, headers={"Retry-After": "3"}, text="upstream down")])
    async with _client(recorder, sleeper) as client:
        response = await client.get(URL)
    assert response.status_code == 503
    assert response.text == "upstream down"
    assert sleeper.calls == []


@pytest.mark.parametrize("status", ["circuit_open", "circuit_half_open"])
async def test_server_circuit_raises_immediately(sleeper: Sleeper, status: str) -> None:
    recorder = Recorder([httpx.Response(503, headers={"X-CSAR-Status": status})])
    async with _client(recorder, sleeper) as client:
        with pytest.raises(CsarCircuitBrokenError) as exc_info:
            await client.get(URL)
    assert exc_info.value.source == "server"
    assert len(recorder.requests) == 1


async def test_legacy_circuit_body_raises(sleeper: Sleeper) -> None:
    recorder = Recorder([httpx.Response(503, json={"error": "circuit breaker open"})])
    async with _client(recorder, sleeper) as client:
        with pytest.raises(CsarCircuitBrokenError):
            await client.get(URL)


async def test_wait_beyond_max_wait_raises(sleeper: Sleeper) -> None:
    recorder = Recorder([throttled(wait_ms=6000)])
    async with _client(recorder, sleeper, max_wait=5.0) as client:
        with pytest.raises(CsarBackpressureError) as exc_info:
            await client.get(URL)
    assert exc_info.value.requested_wait == 6.0
    assert exc_info.value.attempt == 1
    assert sleeper.calls == []


async def test_retries_are_bounded(sleeper: Sleeper) -> None:
    recorder = Recorder(lambda request: throttled(wait_ms=10))
    async with _client(recorder, sleeper, max_retries=2) as client:
        with pytest.raises(CsarBackpressureError) as exc_info:
            await client.get(URL)
    assert exc_info.value.attempt == 3
    assert len(recorder.requests) == 3
    assert sleeper.calls == [0.01, 0.01]


async def test_on_retry_hook_sees_every_retry(sleeper: Sleeper) -> None:
    seen: list[tuple[float, int, int]] = []
    recorder = Recorder([throttled(wait_ms=100), throttled(wait_ms=200), httpx.Response(200)])
    async with _client(
        recorder, sleeper, on_retry=lambda d, a, r: seen.append((d, a, r.status_code))
    ) as client:
        await client.get(URL)
    assert seen == [(0.1, 1, 503), (0.2, 2, 503)]


async def test_post_body_is_replayed_on_retry(sleeper: Sleeper) -> None:
    recorder = Recorder([throttled(wait_ms=5), httpx.Response(200)])
    async with _client(recorder, sleeper) as client:
        await client.post(URL, json={"id": 1})
    assert [json.loads(r.content) for r in recorder.requests] == [{"id": 1}, {"id": 1}]


async def test_client_limit_and_trace_headers(sleeper: Sleeper) -> None:
    recorder = Recorder(lambda request: httpx.Response(200))
    async with _client(recorder, sleeper, client_limit_rps=12.5, generate_trace_id=True) as client:
        await client.get(URL)
        await client.get(URL, headers={"X-Request-Id": "mine"})
    first, second = recorder.requests
    assert first.headers["X-CSAR-Client-Limit"] == "12.5"
    trace_id = first.headers["X-Request-Id"]
    assert len(trace_id) == 32
    assert first.headers["traceparent"].split("-")[1] == trace_id
    assert second.headers["X-Request-Id"] == "mine"


async def test_no_trace_headers_by_default(sleeper: Sleeper) -> None:
    recorder = Recorder(lambda request: httpx.Response(200))
    async with _client(recorder, sleeper) as client:
        await client.get(URL)
    assert "X-Request-Id" not in recorder.requests[0].headers
    assert "X-CSAR-Client-Limit" not in recorder.requests[0].headers


async def test_client_circuit_breaker_opens_after_threshold(sleeper: Sleeper) -> None:
    clock = {"t": 0.0}
    breaker = ClientCircuitBreaker(2, 30.0, clock=lambda: clock["t"])
    recorder = Recorder([httpx.Response(500), httpx.Response(502), httpx.Response(200)])
    async with _client(recorder, sleeper, circuit_breaker=breaker) as client:
        assert (await client.get(URL)).status_code == 500
        assert (await client.get(URL)).status_code == 502
        with pytest.raises(CsarCircuitBrokenError) as exc_info:
            await client.get(URL)
        assert exc_info.value.source == "client"
        clock["t"] = 31.0
        assert (await client.get(URL)).status_code == 200
    assert breaker.state("https://api.example.test") == "closed"
    assert len(recorder.requests) == 3


async def test_half_open_probe_failure_reopens(sleeper: Sleeper) -> None:
    clock = {"t": 0.0}
    breaker = ClientCircuitBreaker(1, 10.0, clock=lambda: clock["t"])
    recorder = Recorder([httpx.Response(500), httpx.Response(500)])
    async with _client(recorder, sleeper, circuit_breaker=breaker) as client:
        await client.get(URL)
        clock["t"] = 11.0
        await client.get(URL)
        with pytest.raises(CsarCircuitBrokenError):
            await client.get(URL)
    assert breaker.state("https://api.example.test") == "open"


async def test_custom_middleware_runs_inside_the_stack(sleeper: Sleeper) -> None:
    async def credential(request: httpx.Request, call_next):  # type: ignore[no-untyped-def]
        request.headers["Authorization"] = "Bearer upstream-key"
        return await call_next(request)

    recorder = Recorder(lambda request: httpx.Response(200))
    async with _client(recorder, sleeper, middlewares=[credential]) as client:
        await client.get(URL)
    assert recorder.requests[0].headers["Authorization"] == "Bearer upstream-key"


async def test_pipeline_order_and_short_circuit() -> None:
    order: list[str] = []

    def named(name: str):  # type: ignore[no-untyped-def]
        async def middleware(request, call_next):  # type: ignore[no-untyped-def]
            order.append(name)
            return await call_next(request)

        return middleware

    async def stop(request, call_next):  # type: ignore[no-untyped-def]
        order.append("stop")
        return httpx.Response(204)

    recorder = Recorder(lambda request: httpx.Response(200))
    transport = PipelineTransport([named("a"), named("b")], recorder.transport)
    async with httpx.AsyncClient(transport=transport) as client:
        assert (await client.get(URL)).status_code == 200
    assert order == ["a", "b"]

    short = PipelineTransport([named("a"), stop, named("never")], recorder.transport)
    async with httpx.AsyncClient(transport=short) as client:
        assert (await client.get(URL)).status_code == 204
    assert order == ["a", "b", "a", "stop"]
    assert len(recorder.requests) == 1


async def test_create_csar_client_resolves_base_url(sleeper: Sleeper) -> None:
    recorder = Recorder(lambda request: httpx.Response(200))
    async with create_csar_client(
        "https://api.example.test/base", max_wait=1, max_retries=0, transport=recorder.transport
    ) as client:
        await client.get("/v1/items")
    assert str(recorder.requests[0].url) == "https://api.example.test/base/v1/items"
