from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from csar import CsarAuthError, CsarTransport, ServiceKey, TokenManager, create_assertion

from .conftest import Sleeper

STS = "https://id.example.test/sts/token"


def _pem(private_key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey) -> str:
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


def _segment(part: str) -> dict:  # type: ignore[type-arg]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _jwt(payload: dict) -> str:  # type: ignore[type-arg]
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"h.{body}.s"


@pytest.fixture
def ed_key() -> tuple[ed25519.Ed25519PrivateKey, ServiceKey]:
    private = ed25519.Ed25519PrivateKey.generate()
    return private, ServiceKey.from_pem("svc:test", _pem(private))


def test_ed25519_assertion_is_signed_and_scoped(ed_key) -> None:  # type: ignore[no-untyped-def]
    private, key = ed_key
    assertion = create_assertion(key, "https://id.example.test", now=1_700_000_000)
    header, payload, signature = assertion.split(".")
    assert _segment(header) == {"alg": "EdDSA", "typ": "JWT"}
    claims = _segment(payload)
    assert claims["iss"] == claims["sub"] == "svc:test"
    assert claims["aud"] == "https://id.example.test"
    assert claims["exp"] - claims["iat"] == 60
    assert claims["jti"]
    private.public_key().verify(
        base64.urlsafe_b64decode(signature + "=="), f"{header}.{payload}".encode()
    )


def test_rs256_authorized_key_json_carries_kid(tmp_path: Path) -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_file = tmp_path / "authorized_key.json"
    key_file.write_text(json.dumps({
        "id": "key-1",
        "service_account_id": "svc:rsa",
        "created_at": "2026-09-28T00:00:00Z",
        "key_algorithm": "RS256",
        "public_key": "",
        "private_key": _pem(private),
    }))
    key = ServiceKey.load(key_file)
    assert key.id == "key-1"
    assertion = create_assertion(key, "aud")
    header, payload, signature = assertion.split(".")
    assert _segment(header) == {"alg": "RS256", "typ": "JWT", "kid": "key-1"}
    private.public_key().verify(
        base64.urlsafe_b64decode(signature + "=="),
        f"{header}.{payload}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_pem_file_needs_an_account(tmp_path: Path, ed_key) -> None:  # type: ignore[no-untyped-def]
    private, _ = ed_key
    pem_file = tmp_path / "sa.key"
    pem_file.write_text(_pem(private))
    with pytest.raises(CsarAuthError) as exc_info:
        ServiceKey.load(pem_file)
    assert exc_info.value.code == "INVALID_CONFIG"
    assert ServiceKey.load(pem_file, service_account_id="svc:x").key_algorithm == "ED25519"


def test_key_validation_and_secret_hiding(ed_key) -> None:  # type: ignore[no-untyped-def]
    private, key = ed_key
    assert "PRIVATE KEY" not in repr(key)
    with pytest.raises(CsarAuthError, match="missing required fields"):
        ServiceKey.from_dict({"service_account_id": "svc", "private_key": _pem(private)})
    with pytest.raises(CsarAuthError, match="unsupported key algorithm"):
        ServiceKey.from_dict({
            "id": "k", "service_account_id": "svc", "private_key": _pem(private),
            "key_algorithm": "ES256",
        })
    with pytest.raises(CsarAuthError, match="does not match"):
        ServiceKey.from_dict({
            "id": "k", "service_account_id": "svc", "private_key": _pem(private),
            "key_algorithm": "RS256",
        })


def test_plain_http_sts_is_refused(ed_key) -> None:  # type: ignore[no-untyped-def]
    _, key = ed_key
    with pytest.raises(CsarAuthError) as exc_info:
        TokenManager(key, sts_endpoint="http://id.example.test/sts/token")
    assert exc_info.value.code == "INVALID_CONFIG"
    TokenManager(key, sts_endpoint="http://localhost:8081/sts/token")


class Sts:
    def __init__(self, clock: dict[str, float]) -> None:
        self.forms: list[dict[str, list[str]]] = []
        self.clock = clock
        self.fail_times = 0
        self.expires_in: object = 900

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.forms.append(parse_qs(request.content.decode()))
        if self.fail_times:
            self.fail_times -= 1
            return httpx.Response(500, text="x" * 500)
        body: dict[str, object] = {"access_token": f"tok-{len(self.forms)}", "token_type": "Bearer"}
        if self.expires_in is not None:
            body["expires_in"] = self.expires_in
        else:
            body["access_token"] = _jwt({"exp": self.clock["t"] + 600})
        return httpx.Response(200, json=body)


def _manager(key: ServiceKey, sts: Sts, clock: dict[str, float], sleeper: Sleeper) -> TokenManager:
    return TokenManager(
        key,
        sts_endpoint=STS,
        sts_audience="https://id.example.test",
        access_token_audience="csar-wb-external",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(sts)),
        clock=lambda: clock["t"],
        sleep=sleeper,
    )


async def test_token_is_cached_and_refreshed_before_expiry(ed_key, sleeper) -> None:  # type: ignore[no-untyped-def]
    _, key = ed_key
    clock = {"t": 1_700_000_000.0}
    sts = Sts(clock)
    manager = _manager(key, sts, clock, sleeper)
    assert await manager.get_token() == "tok-1"
    assert await manager.get_token() == "tok-1"
    form = sts.forms[0]
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
    assert form["audience"] == ["csar-wb-external"]
    assert _segment(form["assertion"][0].split(".")[1])["aud"] == "https://id.example.test"
    clock["t"] += 900 - 300 + 1
    assert await manager.get_token() == "tok-2"


async def test_concurrent_callers_share_one_exchange(ed_key, sleeper) -> None:  # type: ignore[no-untyped-def]
    _, key = ed_key
    clock = {"t": 1_700_000_000.0}
    sts = Sts(clock)
    manager = _manager(key, sts, clock, sleeper)
    tokens = await asyncio.gather(*(manager.get_token() for _ in range(5)))
    assert set(tokens) == {"tok-1"}
    assert len(sts.forms) == 1


async def test_jwt_exp_is_used_when_expires_in_is_missing(ed_key, sleeper) -> None:  # type: ignore[no-untyped-def]
    _, key = ed_key
    clock = {"t": 1_700_000_000.0}
    sts = Sts(clock)
    sts.expires_in = None
    manager = _manager(key, sts, clock, sleeper)
    first = await manager.get_token()
    clock["t"] += 299
    assert await manager.get_token() == first
    clock["t"] += 2
    await manager.get_token()
    assert len(sts.forms) == 2


async def test_sts_failures_back_off_then_raise(ed_key, sleeper) -> None:  # type: ignore[no-untyped-def]
    _, key = ed_key
    clock = {"t": 1_700_000_000.0}
    sts = Sts(clock)
    sts.fail_times = 3
    manager = _manager(key, sts, clock, sleeper)
    with pytest.raises(CsarAuthError) as exc_info:
        await manager.get_token()
    assert exc_info.value.code == "STS_EXCHANGE_FAILED"
    assert len(str(exc_info.value)) < 260
    assert sleeper.calls == [1.0, 2.0]

    sts.fail_times = 1
    assert await manager.get_token() == "tok-5"


async def test_transport_injects_token_and_retries_401_once(ed_key, sleeper) -> None:  # type: ignore[no-untyped-def]
    _, key = ed_key
    clock = {"t": 1_700_000_000.0}
    sts = Sts(clock)
    manager = _manager(key, sts, clock, sleeper)
    seen: list[tuple[str, str]] = []
    statuses = [401, 200]

    def upstream(request: httpx.Request) -> httpx.Response:
        seen.append((request.headers["X-Csar-Authorization"], request.headers["Authorization"]))
        return httpx.Response(statuses.pop(0))

    transport = CsarTransport(
        httpx.MockTransport(upstream), max_wait=1, max_retries=0, auth=manager, sleep=sleeper
    )
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get(
            "https://api.example.test/x", headers={"Authorization": "upstream-credential"}
        )
    assert response.status_code == 200
    assert seen == [
        ("Bearer tok-1", "upstream-credential"),
        ("Bearer tok-2", "upstream-credential"),
    ]
