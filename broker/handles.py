"""Opaque handles for sensitive values.

A handle is HMAC(scope_key, field + value), truncated. The agent sees handles
instead of values and can pass them back; only the broker can resolve one, and
only for a destination the policy allows.

Scope is the whole design decision here:

- `session` (default): the key is derived per session, so the same value in two
  sessions produces two different handles. A handle is useless as a correlation
  identifier outside the session that made it.
- `global`: the key is store-wide, so the same value always produces the same
  handle. This is genuinely useful (deduplication, joining records across
  sessions, caching) and it leaks: two records sharing a handle reveal they
  share a value, and one leaked mapping leaks everywhere that handle appears.

Global scope is supported because the use cases are real. It is not the default
because the leak is silent, and a silent leak in a system that exists to prove
containment is the wrong default.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Literal

HandleScope = Literal["session", "global"]
HANDLE_PREFIX = "hdl_"


class HandleVault:
    def __init__(
        self,
        scope: HandleScope = "session",
        root_key: bytes | None = None,
        session_id: str = "session-local",
    ) -> None:
        if scope not in ("session", "global"):
            raise ValueError(f"unknown handle scope: {scope}")
        self.scope = scope
        self.session_id = session_id
        # A random root key per vault instance keeps handles unguessable. In a
        # real deployment this comes from a KMS and outlives the process.
        self.root_key = root_key or secrets.token_bytes(32)
        # handle -> (field, value, the session it was issued to)
        self._values: dict[str, tuple[str, str, str]] = {}

    def _scope_key(self, session_id: str) -> bytes:
        if self.scope == "global":
            return self.root_key
        return hmac.new(
            self.root_key, session_id.encode("utf-8"), hashlib.sha256
        ).digest()

    def tokenize(self, field: str, value: str, session_id: str | None = None) -> str:
        """Return a stable handle for this (field, value) under the current scope.

        One vault serves every session a broker handles, so the session comes
        with the call. Without it a vault fixed at construction gave two
        sessions the same handle for the same value.
        """
        session = session_id or self.session_id
        digest = hmac.new(
            self._scope_key(session), f"{field}:{value}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        handle = f"{HANDLE_PREFIX}{digest[:16]}"
        self._values[handle] = (field, value, session)
        return handle

    def is_handle(self, candidate: object) -> bool:
        return isinstance(candidate, str) and candidate.startswith(HANDLE_PREFIX)

    def _entry(self, handle: str, session_id: str | None):
        entry = self._values.get(handle)
        if entry is None:
            return None
        # Under session scope a handle is good only in the session it was
        # issued to; another session presenting it is refused as unknown.
        if (self.scope == "session" and session_id is not None
                and entry[2] != session_id):
            return None
        return entry

    def resolve(self, handle: str, session_id: str | None = None) -> str | None:
        """Resolve a handle to its value. Broker-internal; never called from a tool."""
        entry = self._entry(handle, session_id)
        return entry[1] if entry else None

    def field_of(self, handle: str, session_id: str | None = None) -> str | None:
        entry = self._entry(handle, session_id)
        return entry[0] if entry else None

    def redact(self, record: dict, sensitive_fields: set[str],
               session_id: str | None = None) -> dict:
        """Replace sensitive fields in a record with handles, recursively."""
        out: dict = {}
        for key, value in record.items():
            if isinstance(value, dict):
                out[key] = self.redact(value, sensitive_fields, session_id)
            elif key in sensitive_fields and value is not None:
                out[key] = self.tokenize(key, str(value), session_id)
            else:
                out[key] = value
        return out
