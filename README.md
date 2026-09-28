# csar-py

Python SDK for the [CSAR API router](https://github.com/Ledatu/csar): cooperative
backpressure, STS authentication, client-side circuit breaking and request
deduplication for [httpx](https://www.python-httpx.org/). It is the Python
counterpart of [csar-ts](https://github.com/Ledatu/csar-ts) and implements the
router's wire protocol v1 (`docs/PROTOCOL_SPEC.md` in the csar repository).

## Why

CSAR shapes traffic on the server side: a token bucket per route queues requests
up to `max_wait` instead of dropping them, adaptive backpressure pauses the bucket
when the upstream answers `429`, and transparent retry holds the connection
while the upstream's wait passes. When the router cannot absorb the pressure
itself it answers `503` and tells the client how long to wait. This SDK is the
client half of that contract: it waits exactly as long as the router asks,
retries, and stops early when the router reports an open circuit.

## Install

```bash
pip install "csar-py @ https://github.com/Ledatu/csar-py/releases/download/v0.1.0/csar_py-0.1.0-py3-none-any.whl"
```

Python 3.10+, `httpx` and `cryptography` are the only dependencies.

## Quick start

```python
import csar

tokens = csar.TokenManager.from_key_file(
    "authorized_key.json",
    sts_endpoint="https://auth.example.com/sts/token",
    sts_audience="https://auth.example.com",
    access_token_audience="orders-service",
)

async with csar.create_csar_client(
    "https://api.example.com",
    max_wait=5.0,          # give up if the router asks to wait longer than 5 s
    max_retries=3,         # retry a throttled 503 up to 3 times
    auth=tokens,
    client_limit_rps=50,   # advertised as X-CSAR-Client-Limit
) as client:
    response = await client.get("/v1/orders")
```

`CsarTransport` is the same stack as an `httpx.AsyncBaseTransport`, so it can
wrap any inner transport (connection pool settings, TLS context, a mock in
tests) and be handed to an existing `httpx.AsyncClient`:

```python
transport = csar.CsarTransport(
    httpx.AsyncHTTPTransport(verify=ssl_context),
    max_wait=2.0,
    max_retries=2,
    auth=tokens,
    circuit_breaker=csar.ClientCircuitBreaker(threshold=5, reset_timeout=30.0),
    dedup=True,
    generate_trace_id=True,
)
client = httpx.AsyncClient(transport=transport)
```

Service keys come either as the `authorized_key.json` issued by `csar-helper`
(`id`, `service_account_id`, `key_algorithm`, `private_key`) or as a bare PEM
private key plus the service account name:

```python
key = csar.ServiceKey.load("sa.key", service_account_id="svc:orders")
tokens = csar.TokenManager(key, sts_endpoint="https://auth.example.com/sts/token")
```

## Protocol handling

| Router signal | What the SDK does |
|---|---|
| `503` + `X-CSAR-Status: throttled` / `backpressure` | waits and retries; wait = `X-CSAR-Wait-MS`, else `Retry-After`, else body `retry_after_ms`, else 1 s |
| wait > `max_wait`, or more than `max_retries` retries | raises `CsarBackpressureError` (`requested_wait`, `attempt`) |
| `503` + `X-CSAR-Status: circuit_open` / `circuit_half_open` | raises `CsarCircuitBrokenError(source="server")` at once |
| `503` without `X-CSAR-Status` | returned unchanged — an upstream failure, not a router condition |
| `401` | refreshes the STS token and retries once |
| `X-CSAR-Protocol-Version` > 1 | logs a warning |

The priority of `X-CSAR-Wait-MS` over `Retry-After` follows the protocol
specification's priority rules. Router-originated errors share one JSON
envelope (`code`, `status`, `message`, `retry_after_ms`, `request_id`);
`csar.parse_api_error(status, body)` recognises it, which is how a caller tells
"the router refused" from "the upstream answered" on `401`/`403`/`404`.

The STS token travels in `X-Csar-Authorization`, never in `Authorization`: the
router strips it before proxying, and anything the caller puts in
`Authorization` reaches the upstream untouched.

## Middleware pipeline

Like csar-ts, the transport is a pipeline of middlewares, outermost first:
auth → headers → your middlewares → client circuit breaker → dedup → 503 retry.
A middleware is `async (request, call_next) -> response`; `PipelineTransport`
composes any list of them around an inner transport, and the building blocks
(`auth_middleware`, `headers_middleware`, `circuit_breaker_middleware`,
`dedup_middleware`, `retry_middleware`) are exported for custom stacks.

```python
async def upstream_credential(request, call_next):
    request.headers["Authorization"] = f"Bearer {upstream_api_key()}"
    return await call_next(request)

transport = csar.CsarTransport(max_wait=5, max_retries=3, middlewares=[upstream_credential])
```

## Differences from csar-ts

- A `503` without `X-CSAR-Status` is returned to the caller instead of being
  retried, as the protocol specification requires; csar-ts predates the
  specification and treats it as throttled.
- `backpressure` is a recognised `X-CSAR-Status` value, and the error body's
  `retry_after_ms` is used when neither header carries a wait.
- Deduplication keys include a hash of the request's `Authorization` header, so
  two callers with different upstream credentials never share a response.
- A deduplicated request whose leader is cancelled is re-issued by the next
  waiter instead of failing every waiter.
- STS responses without `expires_in` fall back to the token's `exp` claim;
  signing errors are not retried, only the exchange is.
- Async httpx only. The authz permission snapshot of csar-ts
  (`client.permissions()`) is not ported yet.

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy
```

Releases are cut by pushing a `v*` tag: the release workflow runs the suite,
builds the wheel and sdist, and attaches them to a GitHub release.
