"""Egress control: where a value is allowed to go.

Two checks, both deny by default:

1. Destination allowlist. A recipient address or URL host must appear in the
   configured allowlist. An unlisted destination is denied even when the action
   itself is granted, because "send a message" and "send it there" are separate
   authorizations.
2. Handle resolution at the boundary. A handle resolves to its value only when
   the destination is allowed and the field is permitted for that destination.
   The value is substituted on the way out, so it exists in the clear for the
   duration of one outbound call and never inside the agent's context.

This is what closes the exfiltration channel: an agent that has been talked into
addressing a message to an attacker still cannot reach them, and a handle it
passes along resolves to nothing outside an allowed destination.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml


class EgressError(ValueError):
    """Raised at load time for a malformed egress configuration."""


class EgressPolicy:
    def __init__(
        self,
        allowed_recipients: list[str] | None = None,
        allowed_hosts: list[str] | None = None,
        resolvable_fields: dict[str, list[str]] | None = None,
    ) -> None:
        self.allowed_recipients = [r.lower() for r in (allowed_recipients or [])]
        self.allowed_hosts = [h.lower() for h in (allowed_hosts or [])]
        # destination pattern -> fields whose handles may be resolved for it
        self.resolvable_fields = resolvable_fields or {}

    @classmethod
    def from_yaml(cls, path: str | Path) -> "EgressPolicy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        egress = raw.get("egress")
        if egress is None:
            raise EgressError("policy file has no 'egress' section")
        if not isinstance(egress, dict):
            raise EgressError("'egress' must be a mapping")
        return cls(
            allowed_recipients=egress.get("allowed_recipients", []),
            allowed_hosts=egress.get("allowed_hosts", []),
            resolvable_fields=egress.get("resolvable_fields", {}),
        )

    def destination_allowed(self, destination: str) -> bool:
        if not destination:
            return False
        target = destination.strip().lower()

        if "://" in target:
            host = (urlparse(target).hostname or "").lower()
            return any(_matches(host, pattern) for pattern in self.allowed_hosts)

        if "@" in target:
            return any(_matches(target, pattern) for pattern in self.allowed_recipients)

        # Anything that is neither a URL nor an address is not a destination we
        # know how to reason about, so it is refused.
        return False

    def fields_resolvable_for(self, destination: str) -> set[str]:
        target = destination.strip().lower()
        fields: set[str] = set()
        for pattern, allowed in self.resolvable_fields.items():
            if _matches(target, pattern.lower()):
                fields.update(allowed)
        return fields


def _matches(value: str, pattern: str) -> bool:
    """Exact match, or a leading-wildcard domain match such as *@acme.example."""
    if pattern.startswith("*"):
        return value.endswith(pattern[1:])
    return value == pattern
