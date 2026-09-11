"""Consensus Engine — multi-node quorum coordination for Sovereign Engine.

Implements a simple conjunctive-style consensus:
- A proposal only passes if a required fraction of online nodes vote YES.
- Every voting node must itself be locally authorized (alignment ≥ threshold).
- This preserves the Central Security Invariant at mesh scale:
  high-trust majorities cannot override low-alignment states.
"""

from typing import List, Dict, Any, Optional
from network_node import NetworkNode


class ConsensusEngine:
    def __init__(
        self,
        nodes: List[NetworkNode],
        quorum_fraction: float = 0.67,
        min_online: int = 2,
    ):
        if not 0.0 < quorum_fraction <= 1.0:
            raise ValueError("quorum_fraction must be in (0, 1]")
        self.nodes = {n.node_id: n for n in nodes}
        self.quorum_fraction = quorum_fraction
        self.min_online = min_online
        self.round = 0
        self.history: List[Dict[str, Any]] = []

    def _online_nodes(self) -> List[NetworkNode]:
        return [n for n in self.nodes.values() if n.is_online]

    def run_consensus_round(
        self,
        proposal: Dict[str, Any],
        noise_level: float = 0.02,
    ) -> Dict[str, Any]:
        """Execute one full consensus round.

        1. Every online node samples + evaluates locally.
        2. Every online node votes on the proposal.
        3. Quorum is counted only among YES votes from locally-authorized nodes.
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
            }
            self.history.append(result)
            return result

        # Step 1: local sampling & evaluation
        local_states = {}
        for node in online:
            local_states[node.node_id] = node.sample_and_evaluate(noise_level=noise_level)

        # Step 2: collect votes
        votes = []
        yes_votes = 0
        for node in online:
            vote = node.vote(proposal)
            votes.append(vote)
            if vote["vote"] == "YES":
                yes_votes += 1

        required = max(1, int(len(online) * self.quorum_fraction + 0.999))  # ceil

        if yes_votes >= required:
            decision = "ACCEPT"
            reason = f"quorum reached ({yes_votes}/{len(online)}, required {required})"
        else:
            decision = "REJECT"
            reason = f"quorum not reached ({yes_votes}/{len(online)}, required {required})"

        result = {
            "round": self.round,
            "decision": decision,
            "reason": reason,
            "votes": votes,
            "yes_count": yes_votes,
            "online_count": len(online),
            "required": required,
            "local_states": local_states,
            "proposal": proposal,
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
