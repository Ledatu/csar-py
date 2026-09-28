from __future__ import annotations

from typing import Literal

AuthErrorCode = Literal[
    "INVALID_CONFIG",
    "KEY_LOAD_FAILED",
    "INVALID_KEY",
    "ASSERTION_SIGN_FAILED",
    "STS_EXCHANGE_FAILED",
]


class CsarError(Exception):
    pass


class CsarBackpressureError(CsarError):
    def __init__(self, message: str, *, requested_wait: float | None, attempt: int) -> None:
        super().__init__(message)
        self.requested_wait = requested_wait
        self.attempt = attempt


class CsarCircuitBrokenError(CsarError):
    def __init__(self, message: str, *, source: Literal["server", "client"]) -> None:
        super().__init__(message)
        self.source: Literal["server", "client"] = source


class CsarAuthError(CsarError):
    def __init__(self, message: str, code: AuthErrorCode) -> None:
        super().__init__(message)
        self.code: AuthErrorCode = code
