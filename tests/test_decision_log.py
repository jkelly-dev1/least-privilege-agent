"""What the log knows that the agent does not, and why the log can be trusted."""

from __future__ import annotations

import json

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


def test_every_request_writes_exactly_one_record(broker, audit):
    broker.handle(_req())
    broker.handle(_req(subject="stranger"))
    assert len(audit.read_all()) == 2


def test_the_log_names_the_deciding_rule(broker, audit):
    broker.handle(_req())
    assert audit.read_all()[-1].rule_id == "support-read-orders"


def test_the_agent_is_not_told_the_rule_that_denied_it(broker, audit):
    """Denial feedback is a probing oracle, so detail goes to the log only."""
    result = broker.handle(
        _req(
            tool="issue_refund",
            purpose="customer_notification",
            arguments={"amount": "10.00", "currency": "USD"},
        )
    )
    record = audit.read_all()[-1]
    assert result.reason is ReasonCode.PURPOSE_NOT_PERMITTED
    assert "support-refund-small" not in result.message
    assert result.message == "Not permitted for this purpose."
    assert record.detail  # the log gets the specifics
    assert record.decision == "deny"


def test_message_bodies_are_measured_not_quoted_in_the_log(broker, audit):
    body = "sensitive prose the log should not keep"
    broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={"to": "dana.whitfield@acme-customers.example", "body": body},
        )
    )
    record = audit.read_all()[-1]
    assert record.arguments["body"] == f"<{len(body)} chars>"
    assert "sensitive prose" not in json.dumps(record.model_dump())


def test_editing_a_past_record_breaks_the_chain(broker, audit):
    broker.handle(_req())
    broker.handle(_req(subject="stranger"))
    broker.handle(_req())
    assert audit.verify_chain()

    lines = audit.path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["decision"] = "allow"
    lines[1] = json.dumps(tampered)
    audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert audit.verify_chain() is False


def test_a_denied_action_is_still_recorded(broker, audit):
    broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={"to": "attacker@evil.example", "body": "x"},
        )
    )
    record = audit.read_all()[-1]
    assert record.decision == "deny"
    assert record.reason == ReasonCode.DESTINATION_NOT_ALLOWED.value
    assert record.provenance == Provenance.USER.value


def test_the_log_records_the_denial_count_for_probing_detection(broker, audit):
    for _ in range(3):
        broker.handle(_req(subject="stranger"))
    assert audit.read_all()[-1].session_denials == 3
