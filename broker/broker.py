"""The decision point.

Order of checks is part of the design, not an implementation detail:

1. Known tool. An unknown tool is refused before anything else runs.
2. Provenance. Untrusted origin cannot reach a privileged action, whatever the
   policy says, so this is checked before the policy is consulted.
3. Policy. Deny by default; a grant must match subject, purpose, resource, and
   action, and its constraints must hold.
4. Resolve the destination. A recipient may be a handle the agent got from a
   read; it resolves here, inside the broker, and an unknown handle is refused.
5. Egress. The RESOLVED destination must be on the allowlist, separately from
   the action being granted, and the handle's field must be releasable to it.
6. Execute, resolving body handles only at the boundary and only for fields the
   destination is permitted to receive.
7. Record. Every outcome is logged with the rule that decided it, including the
   detail the agent was not told.

A denial short-circuits before step 6, so a denied action never touches the
transport. That ordering is what `test_denied_send_does_not_reach_the_transport`
proves, and it is the difference between a policy engine and a suggestion.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from broker import provenance
from broker.audit import AuditLog
from broker.egress import EgressPolicy
from broker.handles import HandleVault
from broker.models import (
    BrokerResult,
    DecisionRecord,
    DecisionType,
    ReasonCode,
    Request,
)
from broker.policy import Policy
from broker.tools import SENSITIVE_FIELDS, RecordStore, Transport

KNOWN_TOOLS = frozenset({"read_record", "send_message", "write_note", "issue_refund"})

#: Messages the agent sees. Coarse by design: enough to change course, not
#: enough to enumerate the policy one denial at a time.
AGENT_MESSAGES = {
    ReasonCode.NO_GRANT: "Not permitted for this subject.",
    ReasonCode.PURPOSE_NOT_PERMITTED: "Not permitted for this purpose.",
    ReasonCode.CONSTRAINT_EXCEEDED: "Permitted, but a limit on this action was exceeded.",
    ReasonCode.UNTRUSTED_ORIGIN: "Actions derived from retrieved content cannot do this.",
    ReasonCode.DESTINATION_NOT_ALLOWED: "That destination is not allowed.",
    ReasonCode.HANDLE_NOT_RESOLVABLE: "That value cannot be released to this destination.",
    ReasonCode.APPROVAL_REQUIRED: "A human must approve this before it can proceed.",
    ReasonCode.UNKNOWN_TOOL: "No such tool.",
    ReasonCode.INVALID_ARGUMENTS: "The arguments were not valid for this tool.",
}


class Broker:
    def __init__(
        self,
        policy: Policy,
        egress: EgressPolicy,
        records: RecordStore,
        vault: HandleVault,
        audit: AuditLog,
        transport: Transport | None = None,
    ) -> None:
        self.policy = policy
        self.egress = egress
        self.records = records
        self.vault = vault
        self.audit = audit
        self.transport = transport or Transport()
        self._session_spend: dict[str, Decimal] = {}
        self._session_denials: dict[str, int] = {}

    # -- public API ---------------------------------------------------------

    def handle(self, request: Request) -> BrokerResult:
        if request.tool not in KNOWN_TOOLS:
            return self._deny(request, ReasonCode.UNKNOWN_TOOL, "tool is not registered")

        verdict = provenance.check(request)
        if not verdict.allowed:
            return self._deny(request, verdict.reason, verdict.detail)

        match = self.policy.evaluate(
            request, self._session_spend.get(request.session_id, Decimal("0"))
        )

        if match.needs_approval:
            # Not a denial: a pause. The agent is told a human must approve,
            # and nothing is executed until one does.
            self._record(
                request,
                "needs_approval",
                match.reason,
                match.detail,
                rule_id=match.grant.id if match.grant else None,
            )
            return BrokerResult(
                decision="needs_approval",
                reason=ReasonCode.APPROVAL_REQUIRED,
                message=AGENT_MESSAGES[ReasonCode.APPROVAL_REQUIRED],
            )

        if not match.allowed:
            return self._deny(
                request,
                match.reason,
                match.detail,
                rule_id=match.grant.id if match.grant else None,
            )

        rule_id = match.grant.id if match.grant else None
        raw_destination = self._destination_of(request)
        destination = raw_destination

        if raw_destination is not None:
            # A recipient may be a handle the agent received from a read. It is
            # resolved here, inside the broker, before anything is checked
            # against the allowlist: the allowlist governs real addresses, not
            # opaque tokens.
            if self.vault.is_handle(raw_destination):
                resolved = self.vault.resolve(raw_destination)
                field = self.vault.field_of(raw_destination)
                if resolved is None:
                    return self._deny(
                        request,
                        ReasonCode.HANDLE_NOT_RESOLVABLE,
                        "recipient handle is unknown to this broker",
                        rule_id,
                    )
                if field not in self.egress.fields_resolvable_for(resolved):
                    return self._deny(
                        request,
                        ReasonCode.HANDLE_NOT_RESOLVABLE,
                        f"field '{field}' is not releasable to {resolved}",
                        rule_id,
                    )
                destination = resolved

            if not self.egress.destination_allowed(destination or ""):
                return self._deny(
                    request,
                    ReasonCode.DESTINATION_NOT_ALLOWED,
                    f"destination not on the allowlist: {destination}",
                    rule_id,
                )

        return self._execute(request, rule_id, destination)

    # -- internals ----------------------------------------------------------

    def _destination_of(self, request: Request) -> str | None:
        if request.tool == "send_message":
            return str(request.arguments.get("to") or "")
        return None

    def _execute(
        self, request: Request, rule_id: str | None, destination: str | None
    ) -> BrokerResult:
        tool = request.tool
        args = request.arguments

        if tool == "read_record":
            record = self.records.get(request.resource.split("/")[-1])
            if record is None:
                return self._deny(request, ReasonCode.INVALID_ARGUMENTS, "no such order")
            # The agent never sees a raw sensitive value: it sees handles it can
            # pass back to the broker, which is enough to do the job.
            safe = self.vault.redact(record, set(SENSITIVE_FIELDS))
            self._record(request, "redact", ReasonCode.ALLOWED, "record redacted", rule_id)
            return BrokerResult(
                decision="redact", reason=ReasonCode.ALLOWED, output=safe
            )

        if tool == "send_message":
            body = str(args.get("body") or "")
            resolved_to = destination or ""
            body, ok = self._resolve_body(resolved_to, body)
            if not ok:
                return self._deny(
                    request,
                    ReasonCode.HANDLE_NOT_RESOLVABLE,
                    "a handle in the body is not releasable to this destination",
                    rule_id,
                )
            self.transport.send_message(resolved_to, body)
            # The transport knows the resolved address; the agent must not. An
            # earlier version returned the transport's receipt verbatim, which
            # put the customer's real email back into the agent's context one
            # turn after the record had been redacted, undoing the redaction
            # through the confirmation message.
            self._record(request, "allow", ReasonCode.ALLOWED, "message sent", rule_id)
            return BrokerResult(
                decision="allow",
                reason=ReasonCode.ALLOWED,
                output={"delivered": True, "characters": len(body)},
            )

        if tool == "issue_refund":
            amount = Decimal(str(args.get("amount")))
            output = self.transport.issue_refund(
                str(args.get("order_id") or request.resource.split("/")[-1]),
                str(amount),
                str(args.get("currency") or ""),
            )
            self._session_spend[request.session_id] = (
                self._session_spend.get(request.session_id, Decimal("0")) + amount
            )
            self._record(request, "allow", ReasonCode.ALLOWED, "refund issued", rule_id)
            return BrokerResult(decision="allow", reason=ReasonCode.ALLOWED, output=output)

        if tool == "write_note":
            output = self.transport.write_note(
                str(args.get("order_id") or request.resource.split("/")[-1]),
                str(args.get("text") or ""),
            )
            self._record(request, "allow", ReasonCode.ALLOWED, "note written", rule_id)
            return BrokerResult(decision="allow", reason=ReasonCode.ALLOWED, output=output)

        return self._deny(request, ReasonCode.UNKNOWN_TOOL, "unreachable")

    def _resolve_body(self, destination: str, body: str) -> tuple[str, bool]:
        allowed_fields = self.egress.fields_resolvable_for(destination)
        for token in sorted(set(_handles_in(body))):
            field = self.vault.field_of(token)
            if field is None or field not in allowed_fields:
                return body, False
            body = body.replace(token, self.vault.resolve(token) or "")
        return body, True

    def _deny(
        self,
        request: Request,
        reason: ReasonCode,
        detail: str,
        rule_id: str | None = None,
    ) -> BrokerResult:
        self._session_denials[request.session_id] = (
            self._session_denials.get(request.session_id, 0) + 1
        )
        self._record(request, "deny", reason, detail, rule_id)
        return BrokerResult(
            decision="deny",
            reason=reason,
            message=AGENT_MESSAGES.get(reason, "Denied."),
        )

    def _record(
        self,
        request: Request,
        decision: DecisionType,
        reason: ReasonCode,
        detail: str,
        rule_id: str | None = None,
    ) -> None:
        self.audit.append(
            DecisionRecord(
                session_id=request.session_id,
                subject=request.subject,
                purpose=request.purpose,
                tool=request.tool,
                resource=request.resource,
                provenance=request.provenance.value,
                decision=decision,
                reason=reason.value,
                rule_id=rule_id,
                detail=detail,
                arguments=_summarize(request.arguments),
                session_denials=self._session_denials.get(request.session_id, 0),
            )
        )

    def session_denials(self, session_id: str) -> int:
        """Probing signal: repeated denials in one session are worth noticing."""
        return self._session_denials.get(session_id, 0)


def _handles_in(text: str) -> list[str]:
    return [word.strip(".,;:()[]") for word in text.split() if word.startswith("hdl_")]


def _summarize(arguments: dict[str, Any]) -> dict[str, Any]:
    """Log-safe argument summary. Bodies are measured, never quoted."""
    summary: dict[str, Any] = {}
    for key, value in arguments.items():
        if key in ("body", "text"):
            summary[key] = f"<{len(str(value))} chars>"
        else:
            summary[key] = value
    return summary
