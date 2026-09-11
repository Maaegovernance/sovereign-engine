"""Multi-node consensus + identity-bound council + priority integration tests."""

import hmac
import hashlib
import time
import unittest
from network_node import NetworkNode
from consensus_engine import ConsensusEngine
from policy import PolicyRegistry, ObjectiveClass
from evaluator import PolicyEvaluator
from ledger_server import LedgerServer
from council import CouncilRegistry, CouncilMember
from priority import PriorityResolver


class TestConsensusEngine(unittest.TestCase):
    def setUp(self):
        self.nodes = [
            NetworkNode("node-1", initial_trust=0.6),
            NetworkNode("node-2", initial_trust=0.6),
            NetworkNode("node-3", initial_trust=0.6),
        ]

        self.council = CouncilRegistry()
        self.council.add_member(CouncilMember(
            member_id="member-01", role="Sovereign",
            public_secret=b"secret_member_01",
        ))
        self.council.add_member(CouncilMember(
            member_id="member-02", role="SecurityLead",
            public_secret=b"secret_member_02",
        ))
        self.council.add_member(CouncilMember(
            member_id="member-03", role="Architect",
            public_secret=b"secret_member_03",
        ))

        self.registry = PolicyRegistry()
        self.ledger = LedgerServer()
        self.evaluator = PolicyEvaluator(
            registry=self.registry,
            ledger=self.ledger,
            base_alignment_threshold=0.31,
            council_registry=self.council,
        )

        self.engine = ConsensusEngine(
            self.nodes, quorum_fraction=0.67, min_online=2,
            policy_evaluator=self.evaluator,
        )

    def _sig(self, member_id: str, secret: bytes, policy_id: str, requestor: str) -> str:
        payload = f"{policy_id}:{requestor}"
        return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # Core invariant / quorum tests
    # ------------------------------------------------------------------
    def test_basic_quorum_accept(self):
        for n in self.nodes:
            n.force_alignment(0.80)
        result = self.engine.run_consensus_round(proposal={"action": "TEST"})
        self.assertEqual(result["decision"], "ACCEPT")

    def test_alignment_breach_blocks_quorum(self):
        for n in self.nodes:
            n.force_alignment(0.20)
        result = self.engine.run_consensus_round(proposal={"action": "BAD"})
        self.assertEqual(result["decision"], "REJECT")
        for v in result["votes"]:
            self.assertEqual(v["vote"], "NO")

    def test_invariant_holds_under_majority_high_trust(self):
        for n in self.nodes:
            n.governance.trust_score = 0.95
            n.force_alignment(0.22)
        result = self.engine.run_consensus_round(proposal={"action": "TAIP"})
        self.assertEqual(result["decision"], "REJECT")

    # ------------------------------------------------------------------
    # Identity-bound council end-to-end tests
    # ------------------------------------------------------------------
    def test_identity_bound_quorum_passes_high_risk(self):
        """M valid distinct council members → ACCEPT at POLICY gate."""
        for n in self.nodes:
            n.force_alignment(0.80)
            n.governance.trust_score = 0.75

        sig = self._sig("member-01", b"secret_member_01", "POL-ACT-HIGH", "op-1")
        result = self.engine.run_consensus_round(
            proposal={"action": "HIGH_RISK"},
            policy_id="POL-ACT-HIGH",
            requestor_id="op-1",
            signature_map={"member-01": sig},
        )
        self.assertEqual(result["decision"], "ACCEPT")
        self.assertEqual(result["gate"], "POLICY")
        self.assertTrue(result["policy_result"]["authorized"])

    def test_replayed_duplicate_member_attack_fails(self):
        """Same member appearing under two keys must not satisfy M=2."""
        for n in self.nodes:
            n.force_alignment(0.90)
            n.governance.trust_score = 0.85

        sig1 = self._sig("member-01", b"secret_member_01", "POL-CRIT-001", "council")
        # Attacker re-uses the same signature under a second label
        result = self.engine.run_consensus_round(
            proposal={"action": "CRITICAL"},
            policy_id="POL-CRIT-001",
            requestor_id="council",
            signature_map={
                "member-01": sig1,
                "member-01-alias": sig1,  # not a real distinct member
            },
        )
        self.assertEqual(result["decision"], "REJECT")
        self.assertEqual(result["gate"], "POLICY")
        self.assertIn("COUNCIL_QUORUM", result["reason"])

    def test_revoked_member_mid_flight_rejected(self):
        for n in self.nodes:
            n.force_alignment(0.80)
            n.governance.trust_score = 0.75

        sig = self._sig("member-01", b"secret_member_01", "POL-ACT-HIGH", "op-1")
        self.council.revoke_member("member-01")

        result = self.engine.run_consensus_round(
            proposal={"action": "HIGH_RISK"},
            policy_id="POL-ACT-HIGH",
            requestor_id="op-1",
            signature_map={"member-01": sig},
        )
        self.assertEqual(result["decision"], "REJECT")
        self.assertEqual(result["gate"], "POLICY")
        self.assertIn("COUNCIL_QUORUM", result["reason"])

    def test_priority_queue_ordering_under_contention(self):
        """Multiple valid requests ordered CRITICAL > HIGH > LOW > READ_ONLY."""
        now = time.time()
        batch = [
            {"id": "ro", "objective_class": ObjectiveClass.READ_ONLY, "timestamp": now + 3},
            {"id": "crit", "objective_class": ObjectiveClass.CRITICAL_INFRASTRUCTURE, "timestamp": now},
            {"id": "high", "objective_class": ObjectiveClass.HIGH_RISK_ACTUATION, "timestamp": now + 2},
            {"id": "low", "objective_class": ObjectiveClass.LOW_RISK_ACTUATION, "timestamp": now + 1},
        ]
        ordered = self.engine.resolve_priority_queue(batch)
        self.assertEqual([c["id"] for c in ordered], ["crit", "high", "low", "ro"])


if __name__ == "__main__":
    unittest.main()
