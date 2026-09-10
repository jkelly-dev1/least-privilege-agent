"""Grant matching and constraint evaluation. Deny by default, always.

A request is allowed only when some grant matches every one of subject,
purpose, resource, and action, AND the grant's constraints hold. There is no
wildcard subject, no implicit inheritance, and no "probably fine" path. A
policy that grants nothing is a valid policy.

Validation happens at load time so a malformed policy fails at startup rather
than mid-request, when the failure would be a denial nobody planned.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from broker.models import Grant, ReasonCode, Request

# Every constraint key the evaluator understands. An unknown key is a policy
# authoring error, not something to skip quietly: a typo in a constraint name
# would otherwise silently widen the grant.
KNOWN_CONSTRAINTS = frozenset(
    {
        "max_amount",
        "currency",
        "per_session_total",
        "require_human_approval_above",
        "max_recipients",
    }
)


#: Constraints that limit an amount. A grant carrying any of these requires the
#: request to name one.
AMOUNT_CONSTRAINTS = frozenset(
    {"max_amount", "currency", "per_session_total", "require_human_approval_above"}
)


class PolicyError(ValueError):
    """Raised at load time. Never raised during request evaluation."""


class Match:
    """The outcome of evaluating one request against the policy."""

    def __init__(
        self,
        grant: Grant | None,
        reason: ReasonCode,
        detail: str = "",
        needs_approval: bool = False,
    ) -> None:
        self.grant = grant
        self.reason = reason
        self.detail = detail
        self.needs_approval = needs_approval

    @property
    def allowed(self) -> bool:
        return self.grant is not None and self.reason is ReasonCode.ALLOWED


class Policy:
    def __init__(self, grants: list[Grant]) -> None:
        self.grants = grants
        seen: set[str] = set()
        for grant in grants:
            if grant.id in seen:
                raise PolicyError(f"duplicate grant id: {grant.id}")
            seen.add(grant.id)
            unknown = set(grant.constraints) - KNOWN_CONSTRAINTS
            if unknown:
                raise PolicyError(
                    f"grant {grant.id}: unknown constraint(s) {sorted(unknown)}. "
                    f"Known: {sorted(KNOWN_CONSTRAINTS)}"
                )
            if "max_amount" in grant.constraints:
                _as_decimal(grant.constraints["max_amount"], grant.id, "max_amount")
            if "per_session_total" in grant.constraints:
                _as_decimal(
                    grant.constraints["per_session_total"], grant.id, "per_session_total"
                )

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict) or "grants" not in raw:
            raise PolicyError("policy file must be a mapping with a 'grants' key")
        entries = raw["grants"]
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise PolicyError("'grants' must be a list")
        grants = []
        for index, entry in enumerate(entries):
            try:
                grants.append(Grant(**entry))
            except (ValidationError, TypeError) as exc:
                raise PolicyError(f"grant #{index + 1} is invalid: {exc}") from exc
        return cls(grants)

    def evaluate(
        self, request: Request, session_spend: Decimal | None = None
    ) -> Match:
        """Return the match for this request. Deny by default."""
        subject_hits = [g for g in self.grants if g.subject == request.subject]
        if not subject_hits:
            return Match(None, ReasonCode.NO_GRANT, "no grant for subject")

        action_hits = [
            g
            for g in subject_hits
            if g.action == request.tool and fnmatchcase(request.resource, g.resource)
        ]
        if not action_hits:
            return Match(None, ReasonCode.NO_GRANT, "no grant for action or resource")

        purpose_hits = [g for g in action_hits if g.purpose == request.purpose]
        if not purpose_hits:
            # The subject may act on this resource, but not for this purpose.
            # Distinguished from NO_GRANT because purpose laundering is a
            # specific attack and deserves its own line in the log.
            return Match(
                None,
                ReasonCode.PURPOSE_NOT_PERMITTED,
                f"grant exists for this action but not for purpose '{request.purpose}'",
            )

        # Several grants may match; the first that satisfies its constraints
        # wins, so an operator can layer a narrow grant above a broad one.
        last: Match | None = None
        for grant in purpose_hits:
            outcome = self._check_constraints(grant, request, session_spend)
            if outcome.allowed or outcome.needs_approval:
                return outcome
            last = outcome
        return last or Match(None, ReasonCode.NO_GRANT, "no grant matched")

    def _check_constraints(
        self, grant: Grant, request: Request, session_spend: Decimal | None
    ) -> Match:
        constraints = grant.constraints
        amount_raw = request.arguments.get("amount")

        if "max_recipients" in constraints:
            recipients = _recipient_count(request.arguments.get("to"))
            if recipients > int(constraints["max_recipients"]):
                return Match(
                    None,
                    ReasonCode.CONSTRAINT_EXCEEDED,
                    f"more than {constraints['max_recipients']} recipients",
                )

        if amount_raw is None and AMOUNT_CONSTRAINTS & set(constraints):
            # The grant limits an amount, so a request that names none cannot
            # be checked against it. That is a decision, refused and logged,
            # rather than an exception raised somewhere downstream.
            return Match(None, ReasonCode.INVALID_ARGUMENTS, "amount is required")

        if amount_raw is not None:
            try:
                amount = Decimal(str(amount_raw))
            except (InvalidOperation, ValueError):
                return Match(None, ReasonCode.INVALID_ARGUMENTS, "amount is not a number")
            if not amount.is_finite():
                # NaN compares as nothing and Infinity exceeds every cap; both
                # are refused here as arguments so the comparisons below only
                # ever see a number.
                return Match(None, ReasonCode.INVALID_ARGUMENTS, "amount is not finite")
            if amount <= 0:
                return Match(None, ReasonCode.INVALID_ARGUMENTS, "amount must be positive")

            currency = constraints.get("currency")
            if currency and request.arguments.get("currency") != currency:
                return Match(
                    None,
                    ReasonCode.CONSTRAINT_EXCEEDED,
                    f"currency must be {currency}",
                )

            if "max_amount" in constraints:
                cap = Decimal(str(constraints["max_amount"]))
                if amount > cap:
                    return Match(
                        None,
                        ReasonCode.CONSTRAINT_EXCEEDED,
                        f"amount {amount} exceeds per-call cap {cap}",
                    )

            if "per_session_total" in constraints:
                ceiling = Decimal(str(constraints["per_session_total"]))
                spent = session_spend or Decimal("0")
                if spent + amount > ceiling:
                    # This is what stops four small refunds adding up past the
                    # ceiling that one large refund would have hit.
                    return Match(
                        None,
                        ReasonCode.CONSTRAINT_EXCEEDED,
                        f"session total {spent + amount} exceeds ceiling {ceiling}",
                    )

            if "require_human_approval_above" in constraints:
                threshold = Decimal(str(constraints["require_human_approval_above"]))
                if amount > threshold:
                    return Match(
                        grant,
                        ReasonCode.APPROVAL_REQUIRED,
                        f"amount {amount} is above the approval threshold {threshold}",
                        needs_approval=True,
                    )

        return Match(grant, ReasonCode.ALLOWED)


def _recipient_count(value: Any) -> int:
    """How many recipients a `to` argument names.

    A list counts its members. A string counts one per comma- or
    semicolon-separated part, so "a@x.example,b@y.example" is two recipients
    and not one string that happens to end in an approved domain. A display
    name containing a comma is counted as two as well: this check fails
    closed, and the egress layer refuses that form independently.
    """
    if value is None:
        return 0
    if isinstance(value, str):
        return len([part for part in re.split(r"[,;]", value) if part.strip()])
    if isinstance(value, (list, tuple, set)):
        return len(value)
    return 1


def _as_decimal(value: Any, grant_id: str, field: str) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise PolicyError(f"grant {grant_id}: {field} is not a number: {value!r}") from exc
