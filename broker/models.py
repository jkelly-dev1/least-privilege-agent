"""Typed objects for the broker.

The split that matters: `BrokerResult` is what the agent sees, `DecisionRecord`
is what the log sees. The agent gets a coarse reason code so it can adapt; the
rule that decided, the matched grant, and the arguments go to the log only.
Denial feedback is a probing oracle, so the two are deliberately not the same
object.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Provenance(str, Enum):
    """Where a request came from. Ordered by trust, lowest last."""

    TRUSTED_OPERATOR = "trusted_operator"
    USER = "user"
    UNTRUSTED_CONTENT = "untrusted_content"


DecisionType = Literal["allow", "redact", "deny", "needs_approval"]


class ReasonCode(str, Enum):
    """Agent-visible reason codes. Coarse on purpose.

    These tell an agent enough to change course and not enough to map the
    policy one denial at a time.
    """

    ALLOWED = "allowed"
    NO_GRANT = "no_grant"
    PURPOSE_NOT_PERMITTED = "purpose_not_permitted"
    CONSTRAINT_EXCEEDED = "constraint_exceeded"
    UNTRUSTED_ORIGIN = "untrusted_origin"
    DESTINATION_NOT_ALLOWED = "destination_not_allowed"
    HANDLE_NOT_RESOLVABLE = "handle_not_resolvable"
    APPROVAL_REQUIRED = "approval_required"
    UNKNOWN_TOOL = "unknown_tool"
    INVALID_ARGUMENTS = "invalid_arguments"


class Grant(BaseModel):
    """One unit of authority. Absence of a matching grant is a denial."""

    model_config = {"extra": "forbid"}

    id: str
    subject: str
    purpose: str
    resource: str  # glob, matched with fnmatch
    action: str
    constraints: dict[str, Any] = Field(default_factory=dict)


class Request(BaseModel):
    """What the agent proposes. Never executed as given."""

    model_config = {"extra": "forbid"}

    subject: str
    purpose: str
    tool: str
    resource: str = "*"
    arguments: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Provenance.USER
    session_id: str = "session-local"


class BrokerResult(BaseModel):
    """What the agent receives. No rule id, no policy text, no grant list."""

    decision: DecisionType
    reason: ReasonCode
    message: str = ""
    output: Any = None

    @property
    def allowed(self) -> bool:
        return self.decision in ("allow", "redact")


class DecisionRecord(BaseModel):
    """What the audit log receives. Everything, including what the agent
    was not told."""

    session_id: str
    subject: str
    purpose: str
    tool: str
    resource: str
    provenance: str
    decision: DecisionType
    reason: str
    # Populated on an allow or a constraint denial; None when nothing matched.
    rule_id: str | None = None
    detail: str = ""
    # Redacted argument summary. Values never appear here in the clear.
    arguments: dict[str, Any] = Field(default_factory=dict)
    session_denials: int = 0
    prev_hash: str = ""
    record_hash: str = ""

    def payload_for_hash(self) -> dict:
        payload = self.model_dump(mode="json")
        payload.pop("record_hash", None)
        return payload
