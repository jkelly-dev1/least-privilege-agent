"""The bounded agent loop.

The model proposes; the broker decides. Three things about this loop are
security properties rather than implementation details:

1. **The model never chooses the purpose.** Purpose comes from a fixed
   tool-to-purpose table owned by the harness. If the model could name its own
   purpose, purpose binding would be a field an attacker fills in.

2. **The harness assigns provenance, not the model.** Record text read during
   the session is marked untrusted, and the taint tracker decides what that
   makes of any later proposal.

3. **The loop is bounded.** A model that keeps proposing denied actions stops
   at the iteration cap instead of probing forever, and the denial count is on
   the audit record for whoever reads it.

Denials are fed back so the agent can adapt, which is what a real agent must
do, but only as a coarse reason code. The rule that denied it stays in the log.
"""

from __future__ import annotations

import json

from broker.broker import Broker
from broker.llm import Provider, parse_proposal
from broker.models import BrokerResult, Provenance, Request
from broker.taint import TaintTracker

#: Purpose is a property of the calling context, never of the model's claim.
TOOL_PURPOSE = {
    "read_record": "customer_remediation",
    "write_note": "customer_remediation",
    "issue_refund": "customer_remediation",
    "send_message": "customer_notification",
}

MAX_ITERATIONS = 6


class Step:
    def __init__(self, tool: str, provenance: Provenance, result: BrokerResult) -> None:
        self.tool = tool
        self.provenance = provenance
        self.result = result

    @property
    def blocked(self) -> bool:
        return self.result.decision in ("deny", "needs_approval")


class Run:
    def __init__(self, task: str, session_id: str) -> None:
        self.task = task
        self.session_id = session_id
        self.steps: list[Step] = []
        self.answer: str = ""
        self.hit_iteration_cap = False

    @property
    def blocked_steps(self) -> list[Step]:
        return [step for step in self.steps if step.blocked]

    @property
    def executed_tools(self) -> list[str]:
        return [step.tool for step in self.steps if step.result.allowed]


class Agent:
    def __init__(
        self,
        broker: Broker,
        provider: Provider,
        subject: str = "support_agent",
        max_iterations: int = MAX_ITERATIONS,
    ) -> None:
        self.broker = broker
        self.provider = provider
        self.subject = subject
        self.max_iterations = max_iterations

    def run(self, task: str, session_id: str = "s1") -> Run:
        run = Run(task, session_id)
        taint = TaintTracker(task)
        messages = [{"role": "user", "content": task}]

        for iteration in range(self.max_iterations):
            proposal = parse_proposal(self.provider.propose(messages=messages))

            if proposal.get("done") or "tool" not in proposal:
                run.answer = str(proposal.get("answer") or "")
                return run

            tool = str(proposal["tool"])
            arguments = proposal.get("arguments") or {}
            if not isinstance(arguments, dict):
                arguments = {}

            request = Request(
                subject=self.subject,
                purpose=TOOL_PURPOSE.get(tool, "unknown"),
                tool=tool,
                resource=f"order/{arguments.get('order_id', '')}"
                if arguments.get("order_id")
                else "order/*",
                arguments=arguments,
                provenance=taint.provenance_for(
                    Request(
                        subject=self.subject,
                        purpose="probe",
                        tool=tool,
                        arguments=arguments,
                    )
                ),
                session_id=session_id,
            )

            result = self.broker.handle(request)
            run.steps.append(Step(tool, request.provenance, result))

            # A record's own text is untrusted from here on. Everything the
            # agent proposes afterwards is attributed accordingly.
            if result.allowed and tool == "read_record" and isinstance(result.output, dict):
                taint.ingest_untrusted(str(result.output.get("notes") or ""))

            messages.append(
                {
                    "role": "user",
                    "content": f"TOOL RESULT ({tool}): {_summarize(result)}",
                }
            )

        run.hit_iteration_cap = True
        return run


def _summarize(result: BrokerResult) -> str:
    """Tool results reach the model as JSON, not as a Python repr.

    A repr breaks on any apostrophe inside the data, which is exactly what an
    attacker writing free text will produce.
    """
    if result.allowed:
        return "ok " + json.dumps(result.output, default=str)
    return f"{result.decision}: {result.reason.value}. {result.message}"
