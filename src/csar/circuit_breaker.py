from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

import httpx

from .errors import CsarCircuitBrokenError

CircuitState = Literal["closed", "open", "half-open"]


@dataclass
class _OriginState:
    failures: int = 0
    state: CircuitState = "closed"
    opened_at: float = 0.0


class ClientCircuitBreaker:
    """Counts consecutive 5xx responses per origin and short-circuits the origin locally."""

    def __init__(
        self,
        threshold: int,
        reset_timeout: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        self._threshold = threshold
        self._reset_timeout = reset_timeout
        self._clock = clock
        self._origins: dict[str, _OriginState] = {}

    def check(self, origin: str) -> None:
        s = self._origins.get(origin)
        if s is None or s.state != "open":
            return
        if self._clock() - s.opened_at >= self._reset_timeout:
            s.state = "half-open"
            return
        raise CsarCircuitBrokenError(f"client circuit breaker open for {origin}", source="client")

    def on_success(self, origin: str) -> None:
        s = self._origins.get(origin)
        if s is not None:
            s.failures = 0
            s.state = "closed"

    def on_failure(self, origin: str) -> None:
        s = self._origins.setdefault(origin, _OriginState())
        if s.state == "half-open":
            s.state = "open"
            s.opened_at = self._clock()
            return
        s.failures += 1
        if s.failures >= self._threshold:
            s.state = "open"
            s.opened_at = self._clock()

    def state(self, origin: str) -> CircuitState:
        s = self._origins.get(origin)
        return s.state if s is not None else "closed"


def origin_of(url: httpx.URL) -> str:
    return f"{url.scheme}://{url.netloc.decode('ascii')}"
