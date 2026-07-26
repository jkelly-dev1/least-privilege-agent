"""Handle scoping: the correlation tradeoff, made explicit and tested."""

from __future__ import annotations

from broker.handles import HandleVault
from broker.tools import SENSITIVE_FIELDS

KEY = b"a" * 32


def test_a_handle_does_not_contain_the_value():
    vault = HandleVault(root_key=KEY)
    handle = vault.tokenize("card_number", "4111111111111111")
    assert "4111" not in handle
    assert handle.startswith("hdl_")


def test_the_same_value_is_stable_within_a_session():
    vault = HandleVault(root_key=KEY, session_id="s1")
    first = vault.tokenize("email", "a@b.example")
    second = vault.tokenize("email", "a@b.example")
    assert first == second  # the agent can pass a handle back and be understood


def test_session_scope_gives_different_handles_across_sessions():
    """The default. A handle is not a cross-session correlation identifier."""
    one = HandleVault(scope="session", root_key=KEY, session_id="s1")
    two = HandleVault(scope="session", root_key=KEY, session_id="s2")
    assert one.tokenize("email", "a@b.example") != two.tokenize("email", "a@b.example")


def test_global_scope_gives_the_same_handle_across_sessions():
    """The opt-in, and the leak being accepted knowingly.

    Two records sharing a handle reveal they share a value. That is exactly
    what makes global scope useful for deduplication and exactly what makes it
    a correlation risk. The test exists so the tradeoff cannot be forgotten.
    """
    one = HandleVault(scope="global", root_key=KEY, session_id="s1")
    two = HandleVault(scope="global", root_key=KEY, session_id="s2")
    assert one.tokenize("email", "a@b.example") == two.tokenize("email", "a@b.example")


def test_different_fields_with_the_same_value_do_not_collide():
    vault = HandleVault(root_key=KEY)
    assert vault.tokenize("email", "x") != vault.tokenize("phone", "x")


def test_redaction_replaces_every_sensitive_field(records):
    vault = HandleVault(root_key=KEY)
    safe = vault.redact(records.get("4471"), set(SENSITIVE_FIELDS))
    for field in ("card_number", "email", "phone"):
        assert safe[field].startswith("hdl_")
    # Non-sensitive fields survive untouched, or the record stops being useful.
    assert safe["status"] == "refund_pending"
    assert safe["customer_name"] == "Dana Whitfield"


def test_a_raw_sensitive_value_never_appears_in_a_redacted_record(records):
    vault = HandleVault(root_key=KEY)
    original = records.get("4471")
    safe = vault.redact(original, set(SENSITIVE_FIELDS))
    serialized = str(safe)
    assert original["card_number"] not in serialized
    assert original["email"] not in serialized


def test_resolution_is_broker_internal_and_field_aware():
    vault = HandleVault(root_key=KEY)
    handle = vault.tokenize("email", "a@b.example")
    assert vault.resolve(handle) == "a@b.example"
    assert vault.field_of(handle) == "email"
    assert vault.resolve("hdl_not_a_real_handle") is None
