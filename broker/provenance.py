"""The provenance rule: untrusted content cannot raise privilege.

Every request carries where it came from. A request whose origin is
UNTRUSTED_CONTENT (a retrieved document, a tool result, a web page, an issue
comment) may only perform actions on the read-only tier. It can never send,
write, or move money, no matter how convincingly the content asks.

This is the control that makes injection survivable rather than prevented. The
threat model assumes the model will be talked into proposing the action; this
rule means proposing it is not enough.

Note what this deliberately does NOT do: it does not try to detect whether the
content contained an instruction. That classification problem has no reliable
solution, so nothing here depends on solving it. It depends only on knowing
where the text came from, which is a bookkeeping fact the harness controls.
"""

from __future__ import annotations

from broker.models import Provenance, ReasonCode, Request

#: Actions safe to perform on behalf of untrusted content: no side effects
#: outside the boundary, nothing that moves value.
READ_ONLY_ACTIONS = frozenset({"read_record"})

#: Origins allowed to request a privileged action.
TRUSTED_ORIGINS = frozenset({Provenance.TRUSTED_OPERATOR, Provenance.USER})


class ProvenanceVerdict:
    def __init__(self, allowed: bool, reason: ReasonCode, detail: str = "") -> None:
        self.allowed = allowed
        self.reason = reason
        self.detail = detail


def check(request: Request) -> ProvenanceVerdict:
    if request.provenance in TRUSTED_ORIGINS:
        return ProvenanceVerdict(True, ReasonCode.ALLOWED)
    if request.tool in READ_ONLY_ACTIONS:
        return ProvenanceVerdict(True, ReasonCode.ALLOWED)
    return ProvenanceVerdict(
        False,
        ReasonCode.UNTRUSTED_ORIGIN,
        f"action '{request.tool}' was derived from untrusted content",
    )
