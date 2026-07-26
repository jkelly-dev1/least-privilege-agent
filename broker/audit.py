"""Append-only, hash-chained decision log.

The tamper-evidence properties are pinned by the tests in this repository:
editing, reordering, or deleting a record all break verification.

Each record is one JSON line. Before writing, `prev_hash` is set to the
previous record's `record_hash` and this record's hash is computed over its
canonical payload, which includes `prev_hash`. Editing, reordering, or removing
a past record therefore breaks every hash after it, and `verify_chain` reports
the break instead of quietly accepting the file.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from broker.models import DecisionRecord

GENESIS_HASH = "0" * 64


def _hash_payload(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_record_hash(record: DecisionRecord) -> str:
    return _hash_payload(record.payload_for_hash())


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    last = json.loads(line)["record_hash"]
        return last

    def append(self, record: DecisionRecord) -> DecisionRecord:
        record.prev_hash = self._last_hash()
        record.record_hash = compute_record_hash(record)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json() + "\n")
        return record

    def read_all(self) -> list[DecisionRecord]:
        if not self.path.exists():
            return []
        records: list[DecisionRecord] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(DecisionRecord.model_validate_json(line))
        return records

    def verify_chain(self) -> bool:
        """True only if every record hashes correctly and links its predecessor."""
        previous = GENESIS_HASH
        for record in self.read_all():
            if record.prev_hash != previous:
                return False
            if compute_record_hash(record) != record.record_hash:
                return False
            previous = record.record_hash
        return True


def verify_chain(path: str | Path) -> bool:
    return AuditLog(path).verify_chain()
