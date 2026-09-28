from __future__ import annotations

import email.utils

import httpx

from csar import csar_status, parse_api_error, parse_retry_after, protocol_version, wait_time


def test_csar_status_is_case_insensitive_on_name_and_value() -> None:
    assert csar_status(httpx.Headers({"x-csar-status": " Circuit_Open "})) == "circuit_open"
    assert csar_status({"X-CSAR-STATUS": "throttled"}) == "throttled"
    assert csar_status({}) is None
    assert csar_status({"X-CSAR-Status": "  "}) is None


def test_wait_ms_is_the_primary_hint() -> None:
    headers = {"X-CSAR-Wait-MS": "1500", "Retry-After": "7"}
    assert wait_time(headers) == (1.5, "X-CSAR-Wait-MS")


def test_retry_after_is_the_fallback() -> None:
    assert wait_time({"X-CSAR-Wait-MS": "0", "Retry-After": "7"}) == (7.0, "Retry-After")
    assert wait_time({"X-CSAR-Wait-MS": "junk", "Retry-After": "2"}) == (2.0, "Retry-After")
    assert wait_time({}) == (None, "default")


def test_retry_after_accepts_http_date() -> None:
    now = 1_700_000_000.0
    date = email.utils.formatdate(now + 30, usegmt=True)
    assert parse_retry_after(date, now=now) == 30.0
    assert parse_retry_after(email.utils.formatdate(now - 5, usegmt=True), now=now) is None
    assert parse_retry_after("soon", now=now) is None
    assert parse_retry_after("0") is None


def test_api_error_envelope_is_recognised() -> None:
    body = (
        b'{"code":"throttled","status":503,"message":"service temporarily unavailable",'
        b'"retry_after_ms":2500,"request_id":"r1","detail":"queue timeout"}'
    )
    err = parse_api_error(503, body)
    assert err is not None
    assert (err.code, err.status, err.retry_after, err.request_id, err.detail) == (
        "throttled", 503, 2.5, "r1", "queue timeout")


def test_throttle_unavailable_envelope_is_recognised() -> None:
    body = b'{"code":"throttle_unavailable","status":503,"message":"rate limiter unavailable"}'
    err = parse_api_error(503, body)
    assert err is not None and err.code == "throttle_unavailable" and err.retry_after is None


def test_upstream_bodies_are_not_mistaken_for_router_errors() -> None:
    wb = b'{"title":"too many requests","status":429,"statusText":"Too Many Requests","code":"x"}'
    assert parse_api_error(429, wb) is None
    assert parse_api_error(404, b'{"code":"route_not_found","status":503,"message":"m"}') is None
    assert parse_api_error(404, b"not json") is None
    assert parse_api_error(404, b"[]") is None
    assert parse_api_error(404, None) is None


def test_protocol_version() -> None:
    assert protocol_version({"X-CSAR-Protocol-Version": "1"}) == 1
    assert protocol_version({"X-CSAR-Protocol-Version": "v2"}) is None
    assert protocol_version({}) is None
