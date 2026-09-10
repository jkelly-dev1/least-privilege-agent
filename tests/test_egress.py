"""The destination is one parsed address, and the allowlist judges its domain.

A recipient pattern such as "*@acme-customers.example" must approve an address
whose domain component IS that domain, and nothing else: not a longer string
that ends in it, and not a list of addresses one of which is on it. The RFC
display-name form "Dana <dana@...>" is one address and is accepted.
"""

from __future__ import annotations

import pytest

from broker.egress import EgressError, EgressPolicy, parse_recipient

LEGITIMATE = "dana.whitfield@acme-customers.example"
JOINED = [
    f"attacker@evil.example,{LEGITIMATE}",
    f"attacker@evil.example, {LEGITIMATE}",
    f"attacker@evil.example;{LEGITIMATE}",
    f"attacker@evil.example {LEGITIMATE}",
    f"{LEGITIMATE},attacker@evil.example",
    f"Dana <attacker@evil.example>, <{LEGITIMATE}>",
    f"Attacker <attacker@evil.example>, Dana <{LEGITIMATE}>",
]


@pytest.mark.parametrize("to", JOINED)
def test_a_joined_list_ending_in_an_approved_domain_is_refused(egress, to):
    """Mutation check: match the tail of the raw string and this fails."""
    assert parse_recipient(to) is None
    assert egress.destination_allowed(to) is False
    assert egress.fields_resolvable_for(to) == set()


def test_the_display_name_form_is_one_address_and_is_accepted(egress):
    to = f"Dana Whitfield <{LEGITIMATE}>"
    assert parse_recipient(to) == LEGITIMATE
    assert egress.destination_allowed(to) is True
    assert egress.fields_resolvable_for(to) == {"email"}


@pytest.mark.parametrize(
    "to",
    [
        "x@notacme-customers.example",
        "dana@acme-customers.example.evil.example",
        "acme-customers.example",
        "attacker@evil.example",
        "",
    ],
)
def test_a_domain_that_merely_contains_the_approved_one_is_refused(egress, to):
    assert egress.destination_allowed(to) is False


def test_a_recipient_pattern_that_is_not_a_domain_wildcard_fails_at_load():
    """"*acme.example" would be a suffix, and a suffix is what this refuses."""
    with pytest.raises(EgressError, match="one address or"):
        EgressPolicy(allowed_recipients=["*acme-customers.example"])
    with pytest.raises(EgressError, match="one address or"):
        EgressPolicy(resolvable_fields={"*customers.example": ["email"]})
