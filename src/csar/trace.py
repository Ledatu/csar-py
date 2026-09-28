from __future__ import annotations

import secrets


def generate_request_id() -> str:
    return secrets.token_hex(16)


def generate_traceparent() -> tuple[str, str]:
    trace_id = secrets.token_hex(16)
    return trace_id, f"00-{trace_id}-{secrets.token_hex(8)}-01"
