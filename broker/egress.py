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

A destination is checked as ONE parsed address, never as a raw string. A
recipient pattern such as "*@acme.example" is matched against the domain
component of that address, so a joined list that happens to end in an approved
domain is refused as a whole rather than approved by its tail.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

import yaml

# One address: an RFC 5322 dot-atom local part, then exactly one "@", then a
# domain of two or more labels. Nothing in either character class can be a
# separator, so a joined list cannot match.
_ADDRESS = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
# The whole `to`, and only these two shapes: a bare address, or a display
# name wrapping one in angle brackets. The display name may not contain a
# comma, a semicolon or a bracket, so "a@x, Dana <dana@y>" is not a name.
_ONE_RECIPIENT = re.compile(
    rf"^(?:(?P<bare>{_ADDRESS})|(?P<name>[^<>,;]*)<(?P<bracketed>{_ADDRESS})>)$"
)


def parse_recipient(destination: str) -> str | None:
    """The single address in `destination`, lowercased, or None.

    None for anything that is not exactly one address: an empty string, a
    comma-, semicolon- or space-joined list, a URL, a handle, or a display
    name wrapping more than one address. Every egress decision about a
    recipient is made on this value and never on the raw string, so an
    approved domain at the tail of a longer string approves nothing.
    """
    match = _ONE_RECIPIENT.match((destination or "").strip())
    if match is None:
        return None
    return (match.group("bare") or match.group("bracketed")).lower()


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
        for pattern in self.allowed_recipients + [p.lower() for p in self.resolvable_fields]:
            if "://" in pattern or _recipient_pattern_ok(pattern):
                continue
            raise EgressError(
                f"recipient pattern {pattern!r} must be one address or '*@<domain>'"
            )

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

        address = parse_recipient(target)
        if address is not None:
            return any(
                _address_matches(address, pattern) for pattern in self.allowed_recipients
            )

        # Anything that is neither a URL nor exactly one address is not a
        # destination we know how to reason about, so it is refused. That
        # includes a list of addresses: "send it there" is one authorization
        # per destination, and a joined list is not one destination.
        return False

    def fields_resolvable_for(self, destination: str) -> set[str]:
        target = destination.strip().lower()
        address = parse_recipient(target)
        host = (urlparse(target).hostname or "").lower() if "://" in target else None
        fields: set[str] = set()
        for pattern, allowed in self.resolvable_fields.items():
            pattern = pattern.lower()
            if address is not None and _address_matches(address, pattern):
                fields.update(allowed)
            elif host is not None and "://" in pattern and _matches(host, pattern):
                fields.update(allowed)
        return fields


def _recipient_pattern_ok(pattern: str) -> bool:
    if pattern.startswith("*@"):
        return re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", pattern[2:]) is not None
    return parse_recipient(pattern) is not None


def _address_matches(address: str, pattern: str) -> bool:
    """A parsed address against one recipient pattern.

    "*@acme.example" matches when the DOMAIN COMPONENT of the address is
    exactly acme.example. It is compared as a component, not as a suffix of
    the string, so neither "x@evil.example,y@acme.example" nor
    "x@notacme.example" can satisfy it. Any other pattern is one whole
    address and must be equal.
    """
    if pattern.startswith("*@"):
        return address.rpartition("@")[2] == pattern[2:]
    return address == pattern


def _matches(value: str, pattern: str) -> bool:
    """Host match: exact, or a leading-wildcard suffix such as *.acme.example."""
    if pattern.startswith("*"):
        return value.endswith(pattern[1:])
    return value == pattern
