from __future__ import annotations

import asyncio
import base64
import json
import math
import ssl
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .errors import CsarAuthError

KeyAlgorithm = Literal["ED25519", "RS256"]

JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
DEFAULT_ASSERTION_LIFETIME = 60.0
DEFAULT_REFRESH_BUFFER = 300.0
_JWS_ALG = {"ED25519": "EdDSA", "RS256": "RS256"}
_LOCAL_HTTP_PREFIXES = ("http://localhost", "http://127.0.0.1", "http://[::1]")


class TokenSource(Protocol):
    async def get_token(self) -> str: ...

    def clear(self) -> None: ...


@dataclass(frozen=True)
class ServiceKey:
    service_account_id: str
    private_key: str = field(repr=False)
    key_algorithm: KeyAlgorithm
    id: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ServiceKey:
        key_id = data.get("id")
        account = data.get("service_account_id")
        private_key = data.get("private_key")
        algorithm = data.get("key_algorithm")
        if not key_id or not account or not private_key:
            raise CsarAuthError(
                "invalid service key: missing required fields "
                "(id, service_account_id, private_key)",
                "INVALID_KEY",
            )
        if algorithm not in _JWS_ALG:
            raise CsarAuthError(
                f"unsupported key algorithm: {algorithm}; expected ED25519 or RS256", "INVALID_KEY"
            )
        key = cls(
            service_account_id=str(account),
            private_key=str(private_key),
            key_algorithm=algorithm,
            id=str(key_id),
        )
        key.signer()
        return key

    @classmethod
    def from_pem(
        cls, service_account_id: str, pem: bytes | str, *, key_id: str | None = None
    ) -> ServiceKey:
        text = pem.decode("ascii") if isinstance(pem, bytes) else pem
        private = _load_private_key(text)
        algorithm: KeyAlgorithm = (
            "ED25519" if isinstance(private, ed25519.Ed25519PrivateKey) else "RS256"
        )
        return cls(
            service_account_id=service_account_id,
            private_key=text,
            key_algorithm=algorithm,
            id=key_id,
        )

    @classmethod
    def load(cls, path: str | Path, *, service_account_id: str | None = None) -> ServiceKey:
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise CsarAuthError(f"failed to load key file: {exc}", "KEY_LOAD_FAILED") from exc
        if raw.lstrip().startswith(b"{"):
            try:
                data = json.loads(raw)
            except ValueError as exc:
                raise CsarAuthError(
                    f"failed to parse key file as JSON: {path}", "KEY_LOAD_FAILED"
                ) from exc
            return cls.from_dict(data)
        if not service_account_id:
            raise CsarAuthError(
                "a PEM key file needs service_account_id (authorized_key.json carries its own)",
                "INVALID_CONFIG",
            )
        return cls.from_pem(service_account_id, raw)

    def signer(self) -> Callable[[bytes], bytes]:
        private = _load_private_key(self.private_key)
        if self.key_algorithm == "ED25519":
            if not isinstance(private, ed25519.Ed25519PrivateKey):
                raise CsarAuthError("key_algorithm ED25519 does not match the key", "INVALID_KEY")
            return private.sign
        if not isinstance(private, rsa.RSAPrivateKey):
            raise CsarAuthError("key_algorithm RS256 does not match the key", "INVALID_KEY")
        return lambda message: private.sign(message, padding.PKCS1v15(), hashes.SHA256())


def _load_private_key(pem: str) -> ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey:
    try:
        private = load_pem_private_key(pem.encode("ascii"), password=None)
    except (ValueError, TypeError) as exc:
        raise CsarAuthError(
            "failed to import private key: invalid or unsupported PEM format", "INVALID_KEY"
        ) from exc
    if not isinstance(private, (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey)):
        raise CsarAuthError(
            f"unsupported private key type: {type(private).__name__}", "INVALID_KEY"
        )
    return private


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json_segment(value: Mapping[str, Any]) -> str:
    return _b64url(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def create_assertion(
    key: ServiceKey,
    audience: str,
    *,
    lifetime: float = DEFAULT_ASSERTION_LIFETIME,
    now: float | None = None,
) -> str:
    sign = key.signer()
    issued = int(time.time() if now is None else now)
    header: dict[str, Any] = {"alg": _JWS_ALG[key.key_algorithm], "typ": "JWT"}
    if key.id:
        header["kid"] = key.id
    payload = {
        "iss": key.service_account_id,
        "sub": key.service_account_id,
        "aud": audience,
        "jti": str(uuid.uuid4()),
        "iat": issued,
        "exp": issued + int(lifetime),
    }
    signing_input = f"{_json_segment(header)}.{_json_segment(payload)}"
    try:
        signature = sign(signing_input.encode("ascii"))
    except Exception as exc:
        raise CsarAuthError(f"failed to sign assertion: {exc}", "ASSERTION_SIGN_FAILED") from exc
    return f"{signing_input}.{_b64url(signature)}"


def _jwt_exp(token: str) -> float | None:
    try:
        segment = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
        exp = float(payload["exp"])
    except (IndexError, KeyError, TypeError, ValueError):
        return None
    return exp if math.isfinite(exp) else None


def _require_secure(endpoint: str) -> None:
    if endpoint.startswith("https://") or endpoint.startswith(_LOCAL_HTTP_PREFIXES):
        return
    raise CsarAuthError(
        "sts_endpoint must use HTTPS to prevent credential leakage", "INVALID_CONFIG"
    )


class TokenManager:
    """Exchanges signed assertions for CSAR STS access tokens, caching and refreshing them."""

    def __init__(
        self,
        key: ServiceKey,
        *,
        sts_endpoint: str,
        sts_audience: str | None = None,
        access_token_audience: str | None = None,
        max_sts_retries: int = 2,
        refresh_buffer: float = DEFAULT_REFRESH_BUFFER,
        assertion_lifetime: float = DEFAULT_ASSERTION_LIFETIME,
        http_client: httpx.AsyncClient | None = None,
        verify: ssl.SSLContext | str | bool = True,
        timeout: float = 10.0,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        _require_secure(sts_endpoint)
        self._key = key
        self._sts_endpoint = sts_endpoint
        self._sts_audience = sts_audience or sts_endpoint
        self._access_token_audience = access_token_audience
        self._max_sts_retries = max_sts_retries
        self._refresh_buffer = refresh_buffer
        self._assertion_lifetime = assertion_lifetime
        self._http_client = http_client
        self._verify = verify
        self._timeout = timeout
        self._clock = clock
        self._sleep = sleep
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    @classmethod
    def from_key_file(
        cls,
        path: str | Path,
        *,
        sts_endpoint: str,
        service_account_id: str | None = None,
        **kwargs: Any,
    ) -> TokenManager:
        key = ServiceKey.load(path, service_account_id=service_account_id)
        return cls(key, sts_endpoint=sts_endpoint, **kwargs)

    def _fresh(self) -> str | None:
        if self._token is not None and self._clock() < self._expires_at - self._refresh_buffer:
            return self._token
        return None

    async def get_token(self) -> str:
        token = self._fresh()
        if token is not None:
            return token
        async with self._lock:
            token = self._fresh()
            if token is not None:
                return token
            return await self._refresh()

    def clear(self) -> None:
        self._token = None
        self._expires_at = 0.0

    async def _refresh(self) -> str:
        last_error: CsarAuthError | None = None
        for attempt in range(self._max_sts_retries + 1):
            try:
                return await self._exchange()
            except CsarAuthError as exc:
                if exc.code != "STS_EXCHANGE_FAILED":
                    raise
                self.clear()
                last_error = exc
            if attempt < self._max_sts_retries:
                await self._sleep(min(2.0**attempt, 10.0))
        assert last_error is not None
        raise last_error

    async def _exchange(self) -> str:
        now = self._clock()
        form = {
            "grant_type": JWT_BEARER_GRANT,
            "assertion": create_assertion(
                self._key, self._sts_audience, lifetime=self._assertion_lifetime, now=now
            ),
        }
        if self._access_token_audience:
            form["audience"] = self._access_token_audience
        try:
            if self._http_client is not None:
                response = await self._http_client.post(self._sts_endpoint, data=form)
            else:
                async with httpx.AsyncClient(verify=self._verify, timeout=self._timeout) as client:
                    response = await client.post(self._sts_endpoint, data=form)
        except httpx.HTTPError as exc:
            raise CsarAuthError(f"STS request failed: {exc}", "STS_EXCHANGE_FAILED") from exc
        if not response.is_success:
            body = response.text
            safe = body if len(body) <= 200 else body[:200] + "…"
            raise CsarAuthError(
                f"STS returned {response.status_code}: {safe}", "STS_EXCHANGE_FAILED"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise CsarAuthError("STS returned a non-JSON body", "STS_EXCHANGE_FAILED") from exc
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise CsarAuthError(
                "STS returned an invalid token response (missing access_token)",
                "STS_EXCHANGE_FAILED",
            )
        lifetime = _positive_seconds(data.get("expires_in"))
        if lifetime is None:
            exp = _jwt_exp(token)
            lifetime = exp - now if exp is not None and exp > now else None
        if lifetime is None:
            raise CsarAuthError(
                "STS returned an invalid token response (no expires_in or exp)",
                "STS_EXCHANGE_FAILED",
            )
        self._token = token
        self._expires_at = now + lifetime
        return token


def _positive_seconds(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    seconds = float(value)
    return seconds if math.isfinite(seconds) and seconds > 0 else None
