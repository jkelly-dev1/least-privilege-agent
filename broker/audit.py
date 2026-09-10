"""Append-only, hash-chained decision log.

Each record is one JSON line. Before writing, `prev_hash` is set to the
previous record's `record_hash` and this record's hash is computed over its
canonical payload, which includes `prev_hash`.

What `verify_chain` detects, each pinned by a test in this repository: an
edited record, a reordered record, a deleted record anywhere but at the tail,
and a line that is not a record at all (a write that was cut off). What it
cannot detect from the file alone, and does not claim to: a truncated tail,
because a chain that ends early is still a chain, and an editor who rewrites
every hash after the change, because the hash is unkeyed. Both need something
held outside the file, and `verify_chain(expected_last=...)` accepts the last
hash as that anchor: with it, a truncated tail is reported as a break.

A record is written with one `os.write` on an `O_APPEND` descriptor and then
fsynced, so a crash leaves at most one cut-off line at the end. Appending only
reads that tail, so the chain can be extended without re-parsing the file, and
a cut-off tail refuses the append with `AuditLogCorrupt` naming the file and
the line rather than a decode error naming nothing.

Appending takes an exclusive `flock` that spans reading the tail as well as
writing, so two PROCESSES appending to one file chain onto each other instead
of both claiming the same `prev_hash`. The lock is advisory and Unix-only,
which is what this runs on; a writer that does not take it is not held back by
it, so the guarantee is between users of this class.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path

from broker.models import DecisionRecord

GENESIS_HASH = "0" * 64
_TAIL_BYTES = 64 * 1024


class AuditLogCorrupt(ValueError):
    """A line in the log is not a record. Names the file and the line."""

    def __init__(self, path: Path, line: int, why: str) -> None:
        super().__init__(f"{path} line {line} is not a decision record: {why}")
        self.path = path
        self.line = line


def _hash_payload(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_record_hash(record: DecisionRecord) -> str:
    return _hash_payload(record.payload_for_hash())


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # (file size, last record hash) as of the last read or write. The size
        # is what makes the cache safe: a file another writer has grown is
        # re-read rather than chained onto a stale hash.
        self._tail: tuple[int, str] | None = None

    def last_hash(self) -> str:
        """The hash of the last record, read from the tail of the file only.

        Raises AuditLogCorrupt when the tail is not a record. Held outside the
        file, this is the anchor `verify_chain(expected_last=...)` takes.
        """
        if not self.path.exists():
            return GENESIS_HASH
        size = self.path.stat().st_size
        if self._tail is not None and self._tail[0] == size:
            return self._tail[1]
        if size == 0:
            return GENESIS_HASH
        with self.path.open("rb") as handle:
            handle.seek(max(0, size - _TAIL_BYTES))
            chunk = handle.read()
        lines = chunk.split(b"\n")
        # When the file is larger than the chunk, the chunk begins mid-line and
        # the position of a line within it says nothing about its number in
        # the file. A bad tail is then re-read in full so the error names the
        # exact line; the chain itself never needs the number.
        whole_file = size <= _TAIL_BYTES
        for index in range(len(lines) - 1, -1, -1):
            raw = lines[index].strip()
            if not raw:
                continue
            if index == 0 and not whole_file:
                break  # a partial first line of the chunk: read further back
            try:
                last = json.loads(raw)["record_hash"]
            except (ValueError, KeyError, TypeError) as exc:
                if not whole_file:
                    self.read_all()  # raises AuditLogCorrupt with the exact line
                raise AuditLogCorrupt(self.path, index + 1, str(exc)) from exc
            self._tail = (size, last)
            return last
        # Only a partial line fit in the chunk, or nothing did: fall back to a
        # full read, which reports a corrupt line with its exact number.
        records = self.read_all()
        last = records[-1].record_hash if records else GENESIS_HASH
        self._tail = (size, last)
        return last

    def append(self, record: DecisionRecord) -> DecisionRecord:
        """Append one record, chained onto what the file ends with RIGHT NOW.

        THE LOCK SPANS THE READ AS WELL AS THE WRITE, and that span is the
        whole of it. Reading the tail, hashing against it and appending are one
        critical section: a lock around the write alone leaves two processes
        free to read the same tail and then take turns writing, so both records
        claim one `prev_hash` and the chain forks.

        Within a single process the size-keyed tail cache and `O_APPEND` are
        sufficient on their own, so what the lock adds is a guarantee about
        SEPARATE PROCESSES.
        """
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            # EVERYTHING BELOW IS INSIDE THE LOCK. The cache is keyed on file
            # size, so a tail read before another writer grew the file is
            # re-read here rather than chained onto.
            record.prev_hash = self.last_hash()
            record.record_hash = compute_record_hash(record)
            payload = (record.model_dump_json() + "\n").encode("utf-8")
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.fsync(descriptor)
            # STAT INSIDE THE LOCK. Taken after the close, another process
            # could append first and the cache would then hold that writer's
            # size against OUR hash -- a stale tail that chains the next
            # record onto a record that is no longer last.
            size = os.fstat(descriptor).st_size
        finally:
            os.close(descriptor)   # releases the lock
        self._tail = (size, record.record_hash)
        return record

    def read_all(self) -> list[DecisionRecord]:
        """Every record in order. Raises AuditLogCorrupt naming a bad line."""
        if not self.path.exists():
            return []
        records: list[DecisionRecord] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(DecisionRecord.model_validate_json(line))
                except ValueError as exc:
                    raise AuditLogCorrupt(self.path, number, str(exc).splitlines()[0]) from exc
        return records

    def verify_chain(self, expected_last: str | None = None) -> bool:
        """True only if every record hashes correctly and links its predecessor.

        False, never an exception, for a line that is not a record. With
        `expected_last`, also False when the chain does not end on that hash,
        which is the only way a truncated tail can be seen.
        """
        previous = GENESIS_HASH
        try:
            records = self.read_all()
        except AuditLogCorrupt:
            return False
        for record in records:
            if record.prev_hash != previous:
                return False
            if compute_record_hash(record) != record.record_hash:
                return False
            previous = record.record_hash
        if expected_last is not None and previous != expected_last:
            return False
        return True


def verify_chain(path: str | Path, expected_last: str | None = None) -> bool:
    return AuditLog(path).verify_chain(expected_last)
