from __future__ import annotations

from pathlib import Path

import pytest

from broker.audit import AuditLog
from broker.broker import Broker
from broker.egress import EgressPolicy
from broker.handles import HandleVault
from broker.policy import Policy
from broker.tools import RecordStore, Transport

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "policy" / "policy.yaml"
RECORDS_PATH = REPO_ROOT / "data" / "records.yaml"


@pytest.fixture
def policy() -> Policy:
    return Policy.from_yaml(POLICY_PATH)


@pytest.fixture
def egress() -> EgressPolicy:
    return EgressPolicy.from_yaml(POLICY_PATH)


@pytest.fixture
def records() -> RecordStore:
    return RecordStore(RECORDS_PATH)


@pytest.fixture
def transport() -> Transport:
    return Transport()


@pytest.fixture
def vault() -> HandleVault:
    # A fixed root key keeps handles reproducible inside a test run; scope
    # still defaults to per-session, which is the shipped default.
    return HandleVault(scope="session", root_key=b"test-key-32-bytes-long-padding!!")


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "decisions.jsonl")


@pytest.fixture
def broker(policy, egress, records, vault, audit, transport) -> Broker:
    return Broker(policy, egress, records, vault, audit, transport)
