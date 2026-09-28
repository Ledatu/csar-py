from __future__ import annotations

import datetime as dt
import email.utils
import json
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

import httpx

from .constants import (
    ERROR_CODES,
    HEADER_PROTOCOL_VERSION,
    HEADER_RETRY_AFTER,
    HEADER_STATUS,
    HEADER_WAIT_MS,
)

HeadersLike = httpx.Headers | Mapping[str, str]
WaitSource = Literal["X-CSAR-Wait-MS", "Retry-After", "retry_after_ms", "default"]


def get_header(headers: HeadersLike, name: str) -> str | None:
    if isinstance(headers, httpx.Headers):
        value: str | None = headers.get(name)
        return value
    lower = name.lower()
    for key, value in headers.items():
        if key.lower() == lower:
            return value
    return None


def csar_status(headers: HeadersLike) -> str | None:
    raw = get_header(headers, HEADER_STATUS)
    if raw is None:
        return None
    value = raw.strip().lower()
    return value or None


def protocol_version(headers: HeadersLike) -> int | None:
    raw = get_header(headers, HEADER_PROTOCOL_VERSION)
    if raw is None or not raw.strip().isdigit():
        return None
    return int(raw.strip())


def parse_retry_after(value: str, *, now: float | None = None) -> float | None:
    text = value.strip()
    if text.isdigit():
        seconds = int(text)
        return float(seconds) if seconds > 0 else None
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    delta = when.timestamp() - (time.time() if now is None else now)
    return delta if delta > 0 else None


def wait_time(headers: HeadersLike) -> tuple[float | None, WaitSource]:
    raw_ms = get_header(headers, HEADER_WAIT_MS)
    if raw_ms is not None:
        try:
            ms = float(raw_ms.strip())
        except ValueError:
            ms = 0.0
        if math.isfinite(ms) and ms > 0:
            return ms / 1000.0, "X-CSAR-Wait-MS"
    raw_retry = get_header(headers, HEADER_RETRY_AFTER)
    if raw_retry is not None:
        seconds = parse_retry_after(raw_retry)
        if seconds is not None:
            return seconds, "Retry-After"
    return None, "default"


@dataclass(frozen=True)
class ApiError:
    code: str
    status: int
    message: str
    retry_after: float | None = None
    request_id: str | None = None
    detail: str | None = None


def parse_api_error(status_code: int, body: bytes | str | None) -> ApiError | None:
    if not body:
        return None
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    code, message, status = doc.get("code"), doc.get("message"), doc.get("status")
    if code not in ERROR_CODES or not isinstance(message, str) or status != status_code:
        return None
    retry_ms = doc.get("retry_after_ms")
    retry_after = None
    if isinstance(retry_ms, (int, float)) and not isinstance(retry_ms, bool) and retry_ms > 0:
        retry_after = retry_ms / 1000.0
    request_id = doc.get("request_id")
    detail = doc.get("detail")
    return ApiError(
        code=code,
        status=status_code,
        message=message,
        retry_after=retry_after,
        request_id=request_id if isinstance(request_id, str) else None,
        detail=detail if isinstance(detail, str) else None,
    )
