"""Multi-node consensus tests for Sovereign Engine mesh layer.

Verifies:
- Single-node behaviour still respects the 0.31 threshold
- Quorum requirements
- Fault injection (node offline)
- Central Security Invariant cannot be bypassed by a high-trust majority
- End-to-end policy gate (HMAC + metric thresholds) after quorum
"""

import hmac
import hashlib
import unittest
from network_node import NetworkNode
from consensus_engine import ConsensusEngine
from policy import PolicyRegistry
from evaluator import PolicyEvaluator
from ledger_server import LedgerServer


class TestConsensusEngine(unittest.TestCase):
    def setUp(self):
        self.nodes = [
            NetworkNode("node-1", initial_trust=0.6),
            NetworkNode("node-2", initial_trust=0.6),
            NetworkNode("node-3", initial_trust=0.6),
        ]
        self.engine = ConsensusEngine(self.nodes, quorum_fraction=0.67, min_online=2)

        # Policy layer for end-to-end tests
        self.secret = b"sovereign_secret_key"
        self.registry = PolicyRegistry()
        self.ledger = LedgerServer()
        self.evaluator = PolicyEvaluator(
            registry=self.registry,
            ledger=self.ledger,
            shared_secret=self.secret,
            base_alignment_threshold=0.31,
        )
        self.engine_with_policy = ConsensusEngine(
            self.nodes,
            quorum_fraction=0.67,
            min_online=2,
            policy_evaluator=self.evaluator,
        )

    def _sig(self, policy_id: str, requestor: str) -> str:
        payload = f"{policy_id}:{requestor}"
        return hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # Original tests
    # ------------------------------------------------------------------
    def test_basic_quorum_accept(self):
        for n in self.nodes:
            n.force_alignment(0.80)
        result = self.engine.run_consensus_round(proposal={"action": "TEST_DISPATCH"})
        self.assertEqual(result["decision"], "ACCEPT")
        self.assertGreaterEqual(result["yes_count"], result["required"])

    def test_alignment_breach_blocks_quorum(self):
        for n in self.nodes:
            n.force_alignment(0.20)
        result = self.engine.run_consensus_round(proposal={"action": "SHOULD_BE_REJECTED"})
        self.assertEqual(result["decision"], "REJECT")
        for v in result["votes"]:
            self.assertEqual(v["vote"], "NO")

    def test_partial_breach_still_rejects(self):
        self.nodes[0].force_alignment(0.85)
        self.nodes[1].force_alignment(0.15)
        self.nodes[2].force_alignment(0.18)
        result = self.engine.run_consensus_round(proposal={"action": "PARTIAL_BREACH"})
        self.assertEqual(result["decision"], "REJECT")

    def test_node_offline_fault(self):
        for n in self.nodes:
            n.force_alignment(0.80)
        self.engine.inject_fault("node-2", offline=True)
        self.engine.inject_fault("node-3", offline=True)
        result = self.engine.run_consensus_round(proposal={"action": "SHOULD_FAIL_MIN_ONLINE"})
        self.assertEqual(result["decision"], "REJECT")
        self.assertIn("insufficient online nodes", result["reason"])

    def test_single_node_still_respects_threshold(self):
        node = NetworkNode("solo", initial_trust=0.9)
        node.force_alignment(0.25)
        state = node.sample_and_evaluate()
        self.assertFalse(state["authorized"])
        self.assertEqual(state["status"], "HALT_ALIGNMENT_BREACH")

    def test_invariant_holds_under_majority_high_trust(self):
        for n in self.nodes:
            n.governance.trust_score = 0.95
            n.force_alignment(0.22)
        result = self.engine.run_consensus_round(proposal={"action": "TAIP_ATTACK_ATTEMPT"})
        self.assertEqual(result["decision"], "REJECT")
        for v in result["votes"]:
            self.assertEqual(v["vote"], "NO")

    # ------------------------------------------------------------------
    # New end-to-end policy-gate tests
    # ------------------------------------------------------------------
    def test_policy_gate_accepts_valid_high_risk(self):
        """Quorum + valid HMAC + sufficient metrics → ACCEPT."""
        for n in self.nodes:
            n.force_alignment(0.80)
            n.governance.trust_score = 0.75
        sig = self._sig("POL-ACT-HIGH", "operator-1")
        result = self.engine_with_policy.run_consensus_round(
            proposal={"action": "HIGH_RISK_ACT"},
            policy_id="POL-ACT-HIGH",
            requestor_id="operator-1",
            human_signatures=[sig],
        )
        self.assertEqual(result["decision"], "ACCEPT")
        self.assertEqual(result["gate"], "POLICY")
        self.assertTrue(result["policy_result"]["authorized"])

    def test_policy_gate_rejects_missing_signature(self):
        """Quorum passes but missing required human signature → REJECT at POLICY gate."""
        for n in self.nodes:
            n.force_alignment(0.80)
            n.governance.trust_score = 0.75
        result = self.engine_with_policy.run_consensus_round(
            proposal={"action": "HIGH_RISK_ACT"},
            policy_id="POL-ACT-HIGH",
            requestor_id="operator-1",
            human_signatures=[],  # missing
        )
        self.assertEqual(result["decision"], "REJECT")
        self.assertEqual(result["gate"], "POLICY")
        self.assertIn("signature", result["reason"].lower())

    def test_policy_gate_rejects_insufficient_alignment_for_policy(self):
        """Alignment above base 0.31 but below policy-specific 0.65 → REJECT."""
        for n in self.nodes:
            n.force_alignment(0.50)  # > 0.31 but < 0.65
            n.governance.trust_score = 0.70
        sig = self._sig("POL-ACT-HIGH", "operator-1")
        result = self.engine_with_policy.run_consensus_round(
            proposal={"action": "HIGH_RISK_ACT"},
            policy_id="POL-ACT-HIGH",
            requestor_id="operator-1",
            human_signatures=[sig],
        )
        self.assertEqual(result["decision"], "REJECT")
        self.assertEqual(result["gate"], "POLICY")
        self.assertIn("insufficient", result["reason"].lower())

    def test_policy_gate_rejects_spoofed_hmac(self):
        for n in self.nodes:
            n.force_alignment(0.80)
            n.governance.trust_score = 0.75
        result = self.engine_with_policy.run_consensus_round(
            proposal={"action": "HIGH_RISK_ACT"},
            policy_id="POL-ACT-HIGH",
            requestor_id="operator-1",
            human_signatures=["0" * 64],
        )
        self.assertEqual(result["decision"], "REJECT")
        self.assertEqual(result["gate"], "POLICY")
        self.assertIn("Invalid HMAC", result["reason"])


if __name__ == "__main__":
    unittest.main()
