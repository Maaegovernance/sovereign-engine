"""Consensus Engine — multi-node quorum coordination for Sovereign Engine.

Implements a three-gate evaluation pipeline:

  Gate 1: Central Security Invariant (alignment ≥ 0.31) — enforced locally by each node
  Gate 2: Distributed Quorum (N/2+1 online & authorized nodes)
  Gate 3: Semantic Policy & Cryptographic HITL Evaluation (optional PolicyEvaluator)

High-trust majorities cannot override low-alignment states.
"""

from typing import List, Dict, Any, Optional
from network_node import NetworkNode

# Optional import — keeps backward compatibility if policy layer is not present
try:
    from evaluator import PolicyEvaluator
    from policy import EscalationLevel
    _HAS_POLICY = True
except ImportError:
    _HAS_POLICY = False
    PolicyEvaluator = None  # type: ignore
    EscalationLevel = None  # type: ignore


class ConsensusEngine:
    def __init__(
        self,
        nodes: List[NetworkNode],
        quorum_fraction: float = 0.67,
        min_online: int = 2,
        policy_evaluator: Optional["PolicyEvaluator"] = None,
    ):
        if not 0.0 < quorum_fraction <= 1.0:
            raise ValueError("quorum_fraction must be in (0, 1]")
        self.nodes = {n.node_id: n for n in nodes}
        self.quorum_fraction = quorum_fraction
        self.min_online = min_online
        self.policy_evaluator = policy_evaluator
        self.round = 0
        self.history: List[Dict[str, Any]] = []

    def _online_nodes(self) -> List[NetworkNode]:
        return [n for n in self.nodes.values() if n.is_online]

    def run_consensus_round(
        self,
        proposal: Dict[str, Any],
        noise_level: float = 0.02,
        policy_id: Optional[str] = None,
        requestor_id: str = "system",
        human_signatures: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute one full consensus round through the three-gate pipeline.

        1. Every online node samples + evaluates locally (Gate 1).
        2. Every online node votes on the proposal (Gate 2 — quorum).
        3. If a PolicyEvaluator is attached and a policy_id is supplied,
           run semantic + cryptographic evaluation (Gate 3).
        """
        self.round += 1
        online = self._online_nodes()

        if len(online) < self.min_online:
            result = {
                "round": self.round,
                "decision": "REJECT",
                "reason": f"insufficient online nodes ({len(online)} < {self.min_online})",
                "votes": [],
                "online_count": len(online),
                "gate": "QUORUM",
            }
            self.history.append(result)
            return result

        # --- Gate 1 + Gate 2 -------------------------------------------------
        local_states = {}
        for node in online:
            local_states[node.node_id] = node.sample_and_evaluate(noise_level=noise_level)

        votes = []
        yes_votes = 0
        for node in online:
            vote = node.vote(proposal)
            votes.append(vote)
            if vote["vote"] == "YES":
                yes_votes += 1

        required = max(1, int(len(online) * self.quorum_fraction + 0.999))  # ceil

        if yes_votes < required:
            result = {
                "round": self.round,
                "decision": "REJECT",
                "reason": f"quorum not reached ({yes_votes}/{len(online)}, required {required})",
                "votes": votes,
                "yes_count": yes_votes,
                "online_count": len(online),
                "required": required,
                "local_states": local_states,
                "proposal": proposal,
                "gate": "QUORUM",
            }
            self.history.append(result)
            return result

        # Quorum passed. Aggregate alignment / trust from YES voters for Gate 3.
        yes_alignments = []
        yes_trusts = []
        for v in votes:
            if v["vote"] == "YES":
                nid = v["node_id"]
                st = local_states.get(nid, {})
                yes_alignments.append(st.get("alignment", 0.0))
                yes_trusts.append(st.get("trust", 0.0))

        agg_alignment = sum(yes_alignments) / len(yes_alignments) if yes_alignments else 0.0
        agg_trust = sum(yes_trusts) / len(yes_trusts) if yes_trusts else 0.0

        # --- Gate 3 (optional semantic policy) --------------------------------
        policy_result = None
        if (
            self.policy_evaluator is not None
            and policy_id is not None
            and _HAS_POLICY
        ):
            authorized, reason, escalation = self.policy_evaluator.evaluate_command(
                policy_id=policy_id,
                current_alignment=agg_alignment,
                current_trust=agg_trust,
                human_signatures=human_signatures,
                requestor_id=requestor_id,
            )
            policy_result = {
                "authorized": authorized,
                "reason": reason,
                "escalation": escalation.value if hasattr(escalation, "value") else str(escalation),
            }
            if not authorized:
                result = {
                    "round": self.round,
                    "decision": "REJECT",
                    "reason": f"policy gate failed: {reason}",
                    "votes": votes,
                    "yes_count": yes_votes,
                    "online_count": len(online),
                    "required": required,
                    "local_states": local_states,
                    "proposal": proposal,
                    "agg_alignment": agg_alignment,
                    "agg_trust": agg_trust,
                    "policy_result": policy_result,
                    "gate": "POLICY",
                }
                self.history.append(result)
                return result

        # All gates passed
        result = {
            "round": self.round,
            "decision": "ACCEPT",
            "reason": f"quorum reached ({yes_votes}/{len(online)}, required {required})"
                      + (" + policy authorized" if policy_result else ""),
            "votes": votes,
            "yes_count": yes_votes,
            "online_count": len(online),
            "required": required,
            "local_states": local_states,
            "proposal": proposal,
            "agg_alignment": agg_alignment,
            "agg_trust": agg_trust,
            "policy_result": policy_result,
            "gate": "POLICY" if policy_result else "QUORUM",
        }
        self.history.append(result)
        return result

    def get_node(self, node_id: str) -> Optional[NetworkNode]:
        return self.nodes.get(node_id)

    def inject_fault(self, node_id: str, offline: bool = True) -> None:
        """Simple fault injection: take a node offline."""
        node = self.nodes.get(node_id)
        if node:
            node.set_online(not offline)
