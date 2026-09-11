"""Unit tests verifying Phase 3 Sovereign Semantics, HMAC signatures, and Ledger auditing."""

import hmac
import hashlib
import unittest
from policy import PolicyRegistry
from evaluator import PolicyEvaluator
from policy import EscalationLevel
from ledger_server import LedgerServer


class TestSovereignSemantics(unittest.TestCase):
    def setUp(self):
        self.secret = b"sovereign_secret_key"
        self.registry = PolicyRegistry()
        self.ledger = LedgerServer()
        self.evaluator = PolicyEvaluator(
            registry=self.registry,
            ledger=self.ledger,
            shared_secret=self.secret,
            base_alignment_threshold=0.31
        )

    def _generate_sig(self, policy_id: str, requestor_id: str) -> str:
        payload_str = f"{policy_id}:{requestor_id}"
        return hmac.new(
            self.secret, payload_str.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def test_hmac_signature_verification_success(self):
        sig = self._generate_sig("POL-ACT-HIGH", "user-01")
        authorized, msg, level = self.evaluator.evaluate_command(
            policy_id="POL-ACT-HIGH",
            current_alignment=0.75,
            current_trust=0.70,
            human_signatures=[sig],
            requestor_id="user-01"
        )
        self.assertTrue(authorized)
        self.assertEqual(msg, "AUTHORIZED")

    def test_spoofed_signature_rejected(self):
        spoofed_sig = "a" * 64
        authorized, msg, level = self.evaluator.evaluate_command(
            policy_id="POL-ACT-HIGH",
            current_alignment=0.75,
            current_trust=0.70,
            human_signatures=[spoofed_sig],
            requestor_id="user-01"
        )
        self.assertFalse(authorized)
        self.assertIn("Invalid HMAC signature", msg)

    def test_multi_sign_requirement_enforced(self):
        sig1 = self._generate_sig("POL-CRIT-001", "council-01")
        # Only 1 signature provided for POL-CRIT-001 (requires 2)
        authorized, msg, level = self.evaluator.evaluate_command(
            policy_id="POL-CRIT-001",
            current_alignment=0.90,
            current_trust=0.85,
            human_signatures=[sig1],
            requestor_id="council-01"
        )
        self.assertFalse(authorized)
        self.assertIn("requires 2 signature(s)", msg)

    def test_ledger_audit_trail_recorded(self):
        initial_chain_length = len(self.ledger.chain)
        self.evaluator.evaluate_command(
            policy_id="POL-RO-001",
            current_alignment=0.50,
            current_trust=0.20
        )
        self.assertEqual(len(self.ledger.chain), initial_chain_length + 1)
        latest_record = self.ledger.chain[-1]["payload"]
        self.assertEqual(latest_record["event"], "POLICY_EVALUATION")
        self.assertEqual(latest_record["policy_id"], "POL-RO-001")

    def test_base_invariant_still_enforced(self):
        authorized, msg, level = self.evaluator.evaluate_command(
            policy_id="POL-RO-001",
            current_alignment=0.25,
            current_trust=0.90
        )
        self.assertFalse(authorized)
        self.assertIn("Absolute alignment breach", msg)
        self.assertEqual(level, EscalationLevel.HARD_VETO_SYSTEM_HALT)


if __name__ == "__main__":
    unittest.main()
