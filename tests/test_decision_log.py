"""What the log knows that the agent does not, and why the log can be trusted."""

from __future__ import annotations

import json

import pytest

from broker.audit import AuditLog, AuditLogCorrupt, verify_chain
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


def _three_records(broker, audit) -> list[str]:
    broker.handle(_req())
    broker.handle(_req(subject="stranger"))
    broker.handle(_req())
    assert audit.verify_chain()
    return audit.path.read_text(encoding="utf-8").splitlines()


def test_deleting_a_record_from_the_middle_breaks_the_chain(broker, audit):
    """Pins the prev_hash linkage. Mutation check: drop the linkage comparison
    in verify_chain and this fails while the record-hash test still passes."""
    lines = _three_records(broker, audit)
    del lines[1]
    audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert audit.verify_chain() is False


def test_a_truncated_tail_is_seen_only_against_an_anchor(broker, audit):
    """A chain that ends early is still a chain; the last hash held outside
    the file is what exposes it. This is the documented limit, pinned."""
    lines = _three_records(broker, audit)
    anchor = audit.last_hash()
    audit.path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    assert audit.verify_chain() is True
    assert audit.verify_chain(expected_last=anchor) is False
    assert verify_chain(audit.path) is True
    assert verify_chain(audit.path, expected_last=anchor) is False


@pytest.mark.parametrize("extra", [0, 250])
def test_a_torn_tail_line_is_named_and_verify_reports_false(broker, audit, extra):
    """What a kill mid-write leaves behind: half a record, no newline.

    Once with a file that fits in the tail read and once with one that does
    not (250 more records is well past 64 KiB), so the line named is the line
    in the file and not a position inside the chunk that was read.
    """
    lines = _three_records(broker, audit)
    for _ in range(extra):
        audit.append(_record())
    assert (extra == 0) == (audit.path.stat().st_size <= 64 * 1024)
    with audit.path.open("a", encoding="utf-8") as handle:
        handle.write(lines[0][:100])
    fresh = AuditLog(audit.path)
    with pytest.raises(AuditLogCorrupt) as raised:
        fresh.append(_record())
    assert raised.value.path == audit.path
    assert raised.value.line == 4 + extra
    assert str(audit.path) in str(raised.value) and f"line {4 + extra}" in str(raised.value)
    assert fresh.verify_chain() is False
    with pytest.raises(AuditLogCorrupt, match=f"line {4 + extra} is not a decision record"):
        fresh.read_all()


def test_a_torn_middle_line_does_not_stop_later_appends(broker, audit):
    """Only the tail is read to extend the chain, so a bad line behind it
    refuses verification but not the log's job of recording decisions."""
    lines = _three_records(broker, audit)
    lines[1] = lines[1][:60]
    audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    fresh = AuditLog(audit.path)
    appended = fresh.append(_record())
    assert appended.prev_hash == json.loads(lines[2])["record_hash"]
    assert fresh.verify_chain() is False
    with pytest.raises(AuditLogCorrupt, match="line 2 is not a decision record") as raised:
        fresh.read_all()
    assert raised.value.line == 2


def test_appending_from_two_log_objects_chains_correctly(audit):
    """The cached tail is keyed on the file size, so a second writer's record
    is chained onto rather than overwritten in the chain."""
    other = AuditLog(audit.path)
    first = audit.append(_record())
    second = other.append(_record())
    third = audit.append(_record())
    assert second.prev_hash == first.record_hash
    assert third.prev_hash == second.record_hash
    assert audit.verify_chain()


def _append_in_this_process(path_str: str, count: int) -> None:
    """A separate PROCESS appending to the same log file.

    Module level because a child has to be able to reach it. It builds its own
    record rather than calling `_record()` so that nothing here depends on the
    parent's fixtures.
    """
    from broker.audit import AuditLog
    from broker.models import DecisionRecord

    log = AuditLog(path_str)
    for _ in range(count):
        log.append(DecisionRecord(
            session_id="s1", subject="support_agent",
            purpose="customer_remediation", tool="read_record",
            resource="order/4471", provenance="user",
            decision="redact", reason="allowed",
        ))


def test_two_processes_appending_do_not_fork_the_chain(tmp_path):
    """Two PROCESSES appending to one log chain onto each other, not past each
    other.

    Within one process the size-keyed tail cache and `O_APPEND` are enough on
    their own, so a single-process test says nothing about this case. What is
    pinned here is the CROSS-PROCESS lock: without it two processes read the
    same tail and both claim it as `prev_hash`, one record's hash appears twice
    and the chain forks.

    A FORKED CHAIN HAS THE RIGHT NUMBER OF LINES, so the count, the chain and
    the uniqueness of `prev_hash` are asserted separately. With `fcntl.flock`
    defeated and everything else identical, every line is still written and
    `verify_chain()` returns False.
    """
    import multiprocessing as mp

    writers, per_writer = 4, 25
    path = tmp_path / "concurrent.jsonl"
    # fork: flock is Unix-only, so this test is too, and a forked child needs
    # no import of the test module.
    ctx = mp.get_context("fork")
    procs = [ctx.Process(target=_append_in_this_process, args=(str(path), per_writer))
             for _ in range(writers)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout=60)
    assert all(proc.exitcode == 0 for proc in procs), \
        [proc.exitcode for proc in procs]

    log = AuditLog(path)
    records = log.read_all()
    assert len(records) == writers * per_writer

    # THE CHAIN, and not merely the line count. A forked chain has the right
    # number of lines -- that is what makes it worth asserting on separately.
    assert log.verify_chain()
    prevs = [r.prev_hash for r in records]
    assert len(set(prevs)) == len(prevs), "a prev_hash was claimed twice"


def test_the_destination_is_logged_as_its_domain_not_its_local_part(broker, audit):
    """The domain is what the allowlist decided on; the local part is who."""
    broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={"to": "dana.whitfield@acme-customers.example", "body": "x"},
        )
    )
    broker.handle(
        _req(
            tool="send_message",
            purpose="customer_notification",
            arguments={"to": "audit@evil.example", "body": "x"},
        )
    )
    allowed, denied = audit.read_all()[-2:]
    assert allowed.arguments["to"] == "***@acme-customers.example"
    assert denied.arguments["to"] == "***@evil.example"
    assert "audit@evil.example" not in json.dumps(denied.model_dump())
    assert "dana.whitfield" not in json.dumps(allowed.model_dump())


def _record():
    from broker.models import DecisionRecord

    return DecisionRecord(
        session_id="s1", subject="support_agent", purpose="customer_remediation",
        tool="read_record", resource="order/4471", provenance="user",
        decision="redact", reason="allowed",
    )
