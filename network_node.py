"""Network Node — single participant in a multi-node Sovereign Engine mesh.

Each node owns its own GovernanceEngine + SensorNode and can propose
or vote on actions. No node can unilaterally authorize real-world effect.
"""

from typing import Dict, Any, Optional, List
from governance import GovernanceEngine
from sensor_node import SensorNode
from ledger_server import LedgerServer


class NetworkNode:
    def __init__(
        self,
        node_id: str,
        alignment_threshold: float = 0.31,
        initial_trust: float = 0.5,
    ):
        self.node_id = node_id
        self.governance = GovernanceEngine(
            alignment_threshold=alignment_threshold
        )
        self.governance.trust_score = initial_trust
        self.sensor = SensorNode(node_id=node_id)
        self.local_ledger = LedgerServer()  # each node keeps a local view
        self.is_online = True
        self.last_state: Optional[Dict[str, Any]] = None

    def sample_and_evaluate(self, noise_level: float = 0.02) -> Dict[str, Any]:
        """Sample local alignment metric and run the local invariant check."""
        if not self.is_online:
            return {
                "node_id": self.node_id,
                "online": False,
                "authorized": False,
                "status": "NODE_OFFLINE",
            }

        alignment = self.sensor.sample_alignment_metric(noise_level=noise_level)
        authorized, state = self.governance.evaluate_state(alignment)

        state["node_id"] = self.node_id
        state["online"] = True
        state["variance"] = self.sensor.compute_variance_window()

        # Local ledger record
        block_hash = self.local_ledger.record_transition(state)
        state["local_block_hash"] = block_hash

        self.last_state = state
        return state

    def vote(self, proposal: Dict[str, Any]) -> Dict[str, Any]:
        """Cast a vote on a proposed action.

        A node only votes YES if its own local invariant currently authorizes
        and the proposal does not attempt to override the alignment threshold.
        """
        if not self.is_online or self.last_state is None:
            return {
                "node_id": self.node_id,
                "vote": "ABSTAIN",
                "reason": "offline or no local state",
            }

        local_authorized = self.last_state.get("authorized", False)
        local_alignment = self.last_state.get("alignment", 0.0)

        # Hard rule: never vote YES if local alignment is below threshold
        if local_alignment < self.governance.alignment_threshold:
            return {
                "node_id": self.node_id,
                "vote": "NO",
                "reason": "local alignment below threshold",
                "local_alignment": local_alignment,
            }

        if not local_authorized:
            return {
                "node_id": self.node_id,
                "vote": "NO",
                "reason": "local governance not authorized",
            }

        return {
            "node_id": self.node_id,
            "vote": "YES",
            "reason": "local invariant satisfied",
            "local_alignment": local_alignment,
            "local_trust": self.last_state.get("trust"),
        }

    def set_online(self, online: bool) -> None:
        self.is_online = online

    def force_alignment(self, value: float) -> None:
        """Test helper: force the next sample toward a specific alignment."""
        self.sensor.history.append(value)
