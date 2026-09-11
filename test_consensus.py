"""Multi-node consensus tests for Sovereign Engine mesh layer.

Verifies:
- Single-node behaviour still respects the 0.31 threshold
- Quorum requirements
- Fault injection (node offline)
- Central Security Invariant cannot be bypassed by a high-trust majority
  when alignment is below threshold
"""

import unittest
from network_node import NetworkNode
from consensus_engine import ConsensusEngine


class TestConsensusEngine(unittest.TestCase):
    def setUp(self):
        self.nodes = [
            NetworkNode("node-1", initial_trust=0.6),
            NetworkNode("node-2", initial_trust=0.6),
            NetworkNode("node-3", initial_trust=0.6),
        ]
        self.engine = ConsensusEngine(self.nodes, quorum_fraction=0.67, min_online=2)

    def test_basic_quorum_accept(self):
        """All nodes healthy and above threshold → proposal should pass."""
        for n in self.nodes:
            n.force_alignment(0.80)

        result = self.engine.run_consensus_round(
            proposal={"action": "TEST_DISPATCH"}
        )
        self.assertEqual(result["decision"], "ACCEPT")
        self.assertGreaterEqual(result["yes_count"], result["required"])

    def test_alignment_breach_blocks_quorum(self):
        """If all nodes fall below 0.31, even a unanimous high-trust history must reject."""
        for n in self.nodes:
            n.force_alignment(0.20)  # below threshold

        result = self.engine.run_consensus_round(
            proposal={"action": "SHOULD_BE_REJECTED"}
        )
        self.assertEqual(result["decision"], "REJECT")
        # All votes should be NO
        for v in result["votes"]:
            self.assertEqual(v["vote"], "NO")

    def test_partial_breach_still_rejects(self):
        """Majority below threshold → reject even if minority is healthy."""
        self.nodes[0].force_alignment(0.85)
        self.nodes[1].force_alignment(0.15)
        self.nodes[2].force_alignment(0.18)

        result = self.engine.run_consensus_round(
            proposal={"action": "PARTIAL_BREACH"}
        )
        self.assertEqual(result["decision"], "REJECT")

    def test_node_offline_fault(self):
        """Taking nodes offline reduces available quorum."""
        for n in self.nodes:
            n.force_alignment(0.80)

        # Take two nodes offline → only 1 left < min_online=2
        self.engine.inject_fault("node-2", offline=True)
        self.engine.inject_fault("node-3", offline=True)

        result = self.engine.run_consensus_round(
            proposal={"action": "SHOULD_FAIL_MIN_ONLINE"}
        )
        self.assertEqual(result["decision"], "REJECT")
        self.assertIn("insufficient online nodes", result["reason"])

    def test_single_node_still_respects_threshold(self):
        """Even a lone node cannot authorize below the alignment threshold."""
        node = NetworkNode("solo", initial_trust=0.9)
        node.force_alignment(0.25)
        state = node.sample_and_evaluate()
        self.assertFalse(state["authorized"])
        self.assertEqual(state["status"], "HALT_ALIGNMENT_BREACH")

    def test_invariant_holds_under_majority_high_trust(self):
        """Classic TAIP-style attack: high trust scores but low alignment.

        Even if nodes report high trust, the local alignment check must still
        force NO votes when alignment < 0.31.
        """
        for n in self.nodes:
            n.governance.trust_score = 0.95  # artificially high trust
            n.force_alignment(0.22)         # but low alignment

        result = self.engine.run_consensus_round(
            proposal={"action": "TAIP_ATTACK_ATTEMPT"}
        )
        self.assertEqual(result["decision"], "REJECT")
        for v in result["votes"]:
            self.assertEqual(v["vote"], "NO")
            self.assertIn("alignment below threshold", v["reason"])


if __name__ == "__main__":
    unittest.main()
