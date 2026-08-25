"""The worked toolset, and the transport seam that makes denial testable.

Tools never see a credential and never decide anything. They are given already
authorized, already resolved arguments by the broker and do the mechanical work.

The `Transport` indirection exists for one test: a denied send must leave no
trace on the transport. Asserting "the broker returned deny" is weaker than
asserting "nothing reached the wire", and the second is the claim that matters.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

#: Fields replaced with handles before a record reaches the agent.
SENSITIVE_FIELDS = frozenset({"card_number", "email", "phone", "ssn", "iban"})


class Transport:
    """Records outbound effects. A real deployment swaps in SMTP, an API, a bus."""

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.refunds: list[dict[str, Any]] = []
        self.notes: list[dict[str, Any]] = []

    def send_message(self, to: str, body: str) -> dict:
        entry = {"to": to, "body": body}
        self.sent.append(entry)
        return {"delivered_to": to, "characters": len(body)}

    def issue_refund(self, order_id: str, amount: str, currency: str) -> dict:
        entry = {"order_id": order_id, "amount": amount, "currency": currency}
        self.refunds.append(entry)
        return {"refunded": amount, "currency": currency, "order_id": order_id}

    def write_note(self, order_id: str, text: str) -> dict:
        entry = {"order_id": order_id, "text": text}
        self.notes.append(entry)
        return {"note_added_to": order_id, "characters": len(text)}


class RecordStore:
    """Synthetic order records. The only place raw sensitive values live."""

    def __init__(self, path: str | Path) -> None:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        self.records: dict[str, dict] = {
            str(record["order_id"]): record for record in raw.get("orders", [])
        }

    def get(self, order_id: str) -> dict | None:
        return self.records.get(str(order_id))
