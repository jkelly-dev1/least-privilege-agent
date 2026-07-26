"""Untrusted content cannot raise privilege.

This is the control that makes injection survivable. It does not try to detect
an instruction inside text, which has no reliable solution. It acts only on
where the text came from, which the harness knows for certain.
"""

from __future__ import annotations

import pytest

from broker import provenance
from broker.models import Provenance, ReasonCode, Request


def _request(tool: str, origin: Provenance) -> Request:
    return Request(
        subject="support_agent",
        purpose="customer_remediation",
        tool=tool,
        resource="order/4471",
        provenance=origin,
        arguments={"amount": "5.00", "currency": "USD", "to": "x@acme-customers.example"},
    )


@pytest.mark.parametrize("tool", ["send_message", "issue_refund", "write_note"])
def test_untrusted_content_cannot_reach_a_privileged_action(tool):
    """Mutation check: widen READ_ONLY_ACTIONS to include these and it fails."""
    verdict = provenance.check(_request(tool, Provenance.UNTRUSTED_CONTENT))
    assert not verdict.allowed
    assert verdict.reason is ReasonCode.UNTRUSTED_ORIGIN


def test_untrusted_content_may_still_read():
    verdict = provenance.check(_request("read_record", Provenance.UNTRUSTED_CONTENT))
    assert verdict.allowed


@pytest.mark.parametrize(
    "origin", [Provenance.USER, Provenance.TRUSTED_OPERATOR]
)
@pytest.mark.parametrize("tool", ["send_message", "issue_refund", "write_note"])
def test_trusted_origins_reach_the_policy_check(origin, tool):
    """Provenance is a gate, not the decision: trusted origins still face policy."""
    assert provenance.check(_request(tool, origin)).allowed


def test_every_privileged_tool_is_outside_the_read_only_tier():
    """Guard against a tool being added without deciding its trust tier."""
    from broker.broker import KNOWN_TOOLS

    privileged = KNOWN_TOOLS - provenance.READ_ONLY_ACTIONS
    assert privileged == {"send_message", "issue_refund", "write_note"}
