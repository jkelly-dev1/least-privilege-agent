"""Deny by default, purpose binding, and constraint arithmetic."""

from __future__ import annotations

from decimal import Decimal

import pytest

from broker.models import Provenance, ReasonCode, Request
from broker.policy import Policy, PolicyError


def _request(**kwargs) -> Request:
    base = dict(
        subject="support_agent",
        purpose="customer_remediation",
        tool="read_record",
        resource="order/4471",
        provenance=Provenance.USER,
    )
    base.update(kwargs)
    return Request(**base)


def test_matching_request_is_allowed(policy):
    assert policy.evaluate(_request()).allowed


def test_unmatched_request_is_denied_by_default(policy):
    """Mutation check: make evaluate() fall through to allow and this fails."""
    match = policy.evaluate(_request(subject="stranger"))
    assert not match.allowed
    assert match.reason is ReasonCode.NO_GRANT
    assert match.grant is None


def test_purpose_laundering_is_denied(policy):
    """A credential valid for one purpose does not authorize another."""
    match = policy.evaluate(
        _request(tool="issue_refund", purpose="customer_notification",
                 arguments={"amount": "10.00", "currency": "USD"})
    )
    assert not match.allowed
    assert match.reason is ReasonCode.PURPOSE_NOT_PERMITTED


def test_resource_glob_does_not_leak_across_resource_types(policy):
    assert not policy.evaluate(_request(resource="invoice/4471")).allowed


def test_refund_over_the_per_call_cap_is_denied(policy):
    match = policy.evaluate(
        _request(tool="issue_refund", arguments={"amount": "50.01", "currency": "USD"})
    )
    assert not match.allowed
    assert match.reason is ReasonCode.CONSTRAINT_EXCEEDED


def test_refund_at_the_cap_is_permitted(policy):
    match = policy.evaluate(
        _request(tool="issue_refund", arguments={"amount": "50.00", "currency": "USD"})
    )
    # At the cap it is permitted by the amount rule, and lands on the approval
    # gate because 50 is above the 25 threshold.
    assert match.needs_approval


def test_session_ceiling_stops_refunds_adding_up(policy):
    """Four small refunds must not creep past a ceiling one large one would hit."""
    match = policy.evaluate(
        _request(tool="issue_refund", arguments={"amount": "20.00", "currency": "USD"}),
        session_spend=Decimal("90.00"),
    )
    assert not match.allowed
    assert match.reason is ReasonCode.CONSTRAINT_EXCEEDED
    assert "ceiling" in match.detail


def test_wrong_currency_is_denied(policy):
    match = policy.evaluate(
        _request(tool="issue_refund", arguments={"amount": "5.00", "currency": "EUR"})
    )
    assert not match.allowed
    assert match.reason is ReasonCode.CONSTRAINT_EXCEEDED


def test_amount_above_the_threshold_requires_a_human(policy):
    match = policy.evaluate(
        _request(tool="issue_refund", arguments={"amount": "25.01", "currency": "USD"})
    )
    assert match.needs_approval
    assert match.reason is ReasonCode.APPROVAL_REQUIRED


def test_amount_at_or_below_the_threshold_proceeds(policy):
    match = policy.evaluate(
        _request(tool="issue_refund", arguments={"amount": "25.00", "currency": "USD"})
    )
    assert match.allowed
    assert not match.needs_approval


def test_negative_amount_is_rejected(policy):
    match = policy.evaluate(
        _request(tool="issue_refund", arguments={"amount": "-10.00", "currency": "USD"})
    )
    assert not match.allowed
    assert match.reason is ReasonCode.INVALID_ARGUMENTS


def test_unknown_constraint_name_fails_at_load_time(tmp_path):
    """A typo in a constraint must not silently widen a grant."""
    path = tmp_path / "bad.yaml"
    path.write_text(
        "grants:\n"
        "  - id: typo\n"
        "    subject: s\n"
        "    purpose: p\n"
        "    resource: 'order/*'\n"
        "    action: issue_refund\n"
        "    constraints:\n"
        "      max_ammount: 50.00\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="unknown constraint"):
        Policy.from_yaml(path)


def test_unknown_grant_field_fails_at_load_time(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        "grants:\n"
        "  - id: extra\n"
        "    subject: s\n"
        "    purpose: p\n"
        "    resource: '*'\n"
        "    action: read_record\n"
        "    allow_everything: true\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError):
        Policy.from_yaml(path)


def test_duplicate_grant_ids_fail_at_load_time(tmp_path):
    path = tmp_path / "dupe.yaml"
    entry = (
        "  - id: same\n"
        "    subject: s\n"
        "    purpose: p\n"
        "    resource: '*'\n"
        "    action: read_record\n"
    )
    path.write_text("grants:\n" + entry + entry, encoding="utf-8")
    with pytest.raises(PolicyError, match="duplicate"):
        Policy.from_yaml(path)


def test_an_empty_policy_is_valid_and_grants_nothing(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("grants: []\n", encoding="utf-8")
    empty = Policy.from_yaml(path)
    assert not empty.evaluate(_request()).allowed
