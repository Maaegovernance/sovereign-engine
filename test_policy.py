"""Unit tests for Phase 3/4 PolicyEvaluator with identity-bound council signatures."""

import hmac
import hashlib
import unittest
from policy import PolicyRegistry, EscalationLevel
from evaluator import PolicyEvaluator
from ledger_server import LedgerServer
from council import CouncilRegistry, CouncilMember


class TestSovereignSemantics(unittest.TestCase):
    def setUp(self):
        self.registry = PolicyRegistry()
        self.ledger = LedgerServer()

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

        self.evaluator = PolicyEvaluator(
            registry=self.registry,
            ledger=self.ledger,
            base_alignment_threshold=0.31,
            council_registry=self.council,
        )

    def _sig(self, member_id: str, secret: bytes, policy_id: str, requestor: str) -> str:
        payload = f"{policy_id}:{requestor}"
        return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()

    def test_identity_bound_high_risk_authorized(self):
        sig = self._sig("member-01", b"secret_member_01", "POL-ACT-HIGH", "op-1")
        authorized, msg, level = self.evaluator.evaluate_command(
            policy_id="POL-ACT-HIGH",
            current_alignment=0.75,
            current_trust=0.70,
            requestor_id="op-1",
            signature_map={"member-01": sig},
        )
        self.assertTrue(authorized)
        self.assertEqual(msg, "AUTHORIZED")

    def test_multi_sign_critical_requires_two_distinct(self):
        sig1 = self._sig("member-01", b"secret_member_01", "POL-CRIT-001", "council")
        sig2 = self._sig("member-02", b"secret_member_02", "POL-CRIT-001", "council")

        # Only one signature → reject
        ok, msg, _ = self.evaluator.evaluate_command(
            policy_id="POL-CRIT-001",
            current_alignment=0.90,
            current_trust=0.85,
            requestor_id="council",
            signature_map={"member-01": sig1},
        )
        self.assertFalse(ok)
        self.assertIn("COUNCIL_QUORUM", msg)

        # Two distinct → accept
        ok2, msg2, _ = self.evaluator.evaluate_command(
            policy_id="POL-CRIT-001",
            current_alignment=0.90,
            current_trust=0.85,
            requestor_id="council",
            signature_map={"member-01": sig1, "member-02": sig2},
        )
        self.assertTrue(ok2)
        self.assertEqual(msg2, "AUTHORIZED")

    def test_revoked_member_rejected(self):
        self.council.revoke_member("member-01")
        sig = self._sig("member-01", b"secret_member_01", "POL-ACT-HIGH", "op-1")
        ok, msg, _ = self.evaluator.evaluate_command(
            policy_id="POL-ACT-HIGH",
            current_alignment=0.75,
            current_trust=0.70,
            requestor_id="op-1",
            signature_map={"member-01": sig},
        )
        self.assertFalse(ok)
        self.assertIn("COUNCIL_QUORUM", msg)

    def test_no_council_registry_rejects_when_sigs_required(self):
        bare = PolicyEvaluator(
            registry=self.registry,
            ledger=self.ledger,
            base_alignment_threshold=0.31,
            council_registry=None,
        )
        ok, msg, _ = bare.evaluate_command(
            policy_id="POL-ACT-HIGH",
            current_alignment=0.75,
            current_trust=0.70,
            requestor_id="op-1",
            signature_map={"member-01": "abcd"},
        )
        self.assertFalse(ok)
        self.assertEqual(msg, "REJECTED_NO_COUNCIL_REGISTRY")

    def test_base_invariant_still_enforced(self):
        ok, msg, level = self.evaluator.evaluate_command(
            policy_id="POL-RO-001",
            current_alignment=0.25,
            current_trust=0.90,
        )
        self.assertFalse(ok)
        self.assertIn("Absolute alignment breach", msg)
        self.assertEqual(level, EscalationLevel.HARD_VETO_SYSTEM_HALT)

    def test_ledger_audit_trail_recorded(self):
        initial = len(self.ledger.chain)
        self.evaluator.evaluate_command(
            policy_id="POL-RO-001",
            current_alignment=0.50,
            current_trust=0.20,
        )
        self.assertEqual(len(self.ledger.chain), initial + 1)
        latest = self.ledger.chain[-1]["payload"]
        self.assertEqual(latest["event"], "POLICY_EVALUATION")
        self.assertEqual(latest["policy_id"], "POL-RO-001")


if __name__ == "__main__":
    unittest.main()
