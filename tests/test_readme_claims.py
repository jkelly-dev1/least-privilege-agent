"""README.md's own figures about the suite.

The claims table cites tests by node id and the setup block states a test
count. Both are claims about this directory, so they are checked against it.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_every_test_the_readme_cites_exists():
    cited = re.findall(r"`(tests/[\w/]+\.py)::(\w+)", README)
    assert cited, "the claims table cites no test"
    missing = []
    for path, name in cited:
        source = (ROOT / path).read_text(encoding="utf-8")
        if not re.search(rf"^def {name}\(", source, re.M):
            missing.append(f"{path}::{name}")
    assert missing == [], f"README cites tests that do not exist: {missing}"


def test_the_stated_test_count_is_the_collected_count():
    stated = re.search(r"pytest -q\s+# (\d+) tests", README)
    assert stated, "README no longer states a test count"
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    ).stdout
    collected = int(re.search(r"(\d+) tests? collected", out).group(1))
    assert int(stated.group(1)) == collected


# The coverage figures, each anchored to the words around it so that every
# pattern matches exactly one sentence. The measured values come from the
# same in-process patches tests/test_defense_in_depth.py uses.
WORDS = {"two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
         "eight": 8, "nine": 9, "ten": 10}
FIGURES = {
    "releasability_contains": r"\*\*Handle releasability alone\*\* contains (\d+) of \d+\.",
    "releasability_of": r"\*\*Handle releasability alone\*\* contains \d+ of (\d+)\.",
    "refunds_each": r"(\w+) refunds of ([\d.]+), inside the policy's limits",
    "releasability_escape": r"The one that gets past it is `([\w-]+)`",
    "egress_contains": r"\*\*Egress alone\*\* contains (\d+) of \d+\.",
    "egress_of": r"\*\*Egress alone\*\* contains \d+ of (\d+)\.",
    "egress_cards": r"and (\d+) attacks still get the raw card number",
    "egress_remaining": r"The remaining one is `([\w-]+)`, whose (\w+) small refunds",
    "provenance_cards": r"the same (\d+) card-number releases get past it",
    "all_off_escaped": r"With all three disabled, (\d+) of \d+ attacks get through",
    "all_off_of": r"With all three disabled, \d+ of (\d+) attacks get through",
    "corpus_size": r"The corpus is (\d+) payloads across \w+ categories",
    "corpus_categories": r"The corpus is \d+ payloads across (\w+) categories",
}


def _number(text: str) -> int:
    return int(text) if text.isdigit() else WORDS[text.lower()]


def _stated(pattern: str, text: str) -> str:
    found = re.findall(pattern, text)
    assert len(found) == 1, f"{pattern!r} matches {len(found)} sentences, not 1"
    return found[0]


def test_the_coverage_figures_are_the_measured_ones(tmp_path):
    from test_defense_in_depth import (
        REFUNDS,
        _allow_all_destinations,
        _allow_all_provenance,
        _card_releases_only,
        _release_every_field,
        _report,
    )

    readme = " ".join(README.split())
    description = (ROOT / "GITHUB_DESCRIPTION.txt").read_text(encoding="utf-8")

    releasability = _report(tmp_path / "r", _allow_all_provenance,
                            _allow_all_destinations)
    egress = _report(tmp_path / "e", _allow_all_provenance, _release_every_field)
    provenance = _report(tmp_path / "p", _allow_all_destinations,
                         _release_every_field)
    all_off = _report(tmp_path / "a", _allow_all_provenance,
                      _allow_all_destinations, _release_every_field)
    size = len(all_off.attacks)
    refunds, total = re.fullmatch(
        r"(\d+) refund\(s\) totaling ([\d.]+) from a task that asked for none",
        REFUNDS).groups()

    measured = {
        "releasability_contains": sum(a.contained for a in releasability.attacks),
        "releasability_of": size,
        "egress_contains": sum(a.contained for a in egress.attacks),
        "egress_of": size,
        "egress_cards": sum(_card_releases_only(a)
                            for a in egress.attacks if not a.contained),
        "provenance_cards": sum(_card_releases_only(a)
                                for a in provenance.attacks
                                if not a.contained and a.category != "A1"),
        "all_off_escaped": sum(not a.contained for a in all_off.attacks),
        "all_off_of": size,
        "corpus_size": size,
        "corpus_categories": len({a.category for a in all_off.attacks}),
    }
    stated = {name: _number(_stated(FIGURES[name], readme)) for name in measured}
    assert stated == measured

    # The attack each partial configuration lets through besides the card
    # releases, and the refunds it makes, as the two bullets name them.
    count, each = _stated(FIGURES["refunds_each"], readme)
    assert _number(count) == int(refunds)
    assert f"{_number(count) * float(each):.2f}" == total
    assert [a.id for a in releasability.attacks if not a.contained] == [
        _stated(FIGURES["releasability_escape"], readme)]
    remaining, small = _stated(FIGURES["egress_remaining"], readme)
    assert [a.id for a in egress.attacks
            if not a.contained and not _card_releases_only(a)] == [remaining]
    assert _number(small) == int(refunds)

    payloads = _stated(r"(\d+)-payload attack corpus", description)
    assert int(payloads) == size
