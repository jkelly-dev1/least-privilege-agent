"""Assigning provenance to a proposal.

The broker needs to know where a proposed action came from. That is a
bookkeeping question the harness can answer, not a classification question the
model has to solve, and the distinction is the whole reason this design works.

The rule, in order:

1. Before any untrusted content has entered the session, a proposal is USER.
2. Once untrusted content has been read, the session is tainted. A privileged
   proposal is then USER only if its consequential arguments can be traced back
   to the operator's own instruction. Otherwise it is UNTRUSTED_CONTENT.

Consequential arguments are the ones that decide who is affected and by how
much: the recipient and the amount. Body text is not consequential for this
purpose; an attacker who can only change wording has not gained a capability.

This is a heuristic operating at Boundary A, and the threat model is explicit
that Boundary A cannot be made airtight. Two things make that acceptable:

- It fails closed. When attribution is uncertain the answer is
  UNTRUSTED_CONTENT, which costs an over-denial rather than a leak.
- It is not the only control. Even a misclassified proposal still faces the
  policy, the constraint checks, and the egress allowlist. Taint tracking is
  the first of four gates, not the gate.
"""

from __future__ import annotations

import re

from broker.models import Provenance, Request

CONSEQUENTIAL_ARGUMENTS = ("to", "amount", "order_id")

_WORD = re.compile(r"[a-z0-9@._+-]+")


def _tokens(text: str) -> set[str]:
    """Tokenize, stripping trailing sentence punctuation.

    Without the strip, an operator who names a recipient at the end of a
    sentence ("...let dana@acme.example know.") produces the token
    "dana@acme.example." with a trailing period, which never matches the
    address in the proposal. The failure direction is safe (an over-denial)
    but it makes the tracker useless for ordinary phrasing.
    """
    return {
        token.rstrip(".,;:!?")
        for token in _WORD.findall((text or "").lower())
        if token.rstrip(".,;:!?")
    }


class TaintTracker:
    """Tracks whether untrusted content has entered a session."""

    def __init__(self, instruction: str) -> None:
        self.instruction = instruction
        self._instruction_tokens = _tokens(instruction)
        self.tainted = False
        self.untrusted_sources: list[str] = []

    def ingest_untrusted(self, text: str) -> None:
        """Record that untrusted content has entered the agent's context."""
        if text:
            self.tainted = True
            self.untrusted_sources.append(text)

    def provenance_for(self, request: Request) -> Provenance:
        if not self.tainted:
            return Provenance.USER

        for name in CONSEQUENTIAL_ARGUMENTS:
            value = request.arguments.get(name)
            if value is None:
                continue
            if not self._traceable_to_instruction(str(value)):
                return Provenance.UNTRUSTED_CONTENT

        return Provenance.USER

    def _traceable_to_instruction(self, value: str) -> bool:
        """True when every token of the value appears in the operator's ask.

        A handle counts as traceable: the agent can only hold one because the
        broker gave it out during this session, and resolving it is still
        subject to the egress rules.
        """
        if value.startswith("hdl_"):
            return True
        value_tokens = _tokens(value)
        if not value_tokens:
            return True
        return value_tokens <= self._instruction_tokens
