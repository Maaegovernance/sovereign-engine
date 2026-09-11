"""Unit tests verifying hard enforcement of Central Security Invariant and Trust-Alignment Inversion protections."""

import unittest
from governance import GovernanceEngine

class TestGovernanceEngine(unittest.TestCase):
    def setUp(self):
        # Initialize at safety boundary threshold to mitigate bootstrap risk
        self.engine = GovernanceEngine(alignment_threshold=0.31, trust_decay_rate=0.05)
        self.engine.trust_score = 0.2

    def test_invariant_hard_enforcement_below_threshold(self):
        """Verify execution is strictly vetoed whenever alignment drops below 0.31."""
        authorized, state = self.engine.evaluate_state(current_alignment=0.30)
        self.assertFalse(authorized)
        self.assertEqual(state["status"], "HALT_ALIGNMENT_BREACH")

    def test_trust_degradation_asymmetry(self):
        """Verify trust decays rapidly during degradation and recovers slowly."""
        # Baseline step
        self.engine.evaluate_state(0.80)
        initial_trust = self.engine.trust_score

        # Drop alignment
        _, drop_state = self.engine.evaluate_state(0.70)
        trust_after_drop = drop_state["trust"]
        drop_loss = initial_trust - trust_after_drop

        # Recover alignment by equal magnitude
        _, recover_state = self.engine.evaluate_state(0.80)
        trust_after_recovery = recover_state["trust"]
        recovery_gain = trust_after_recovery - trust_after_drop

        # Assert asymmetry (decay loss > recovery gain)
        self.assertGreater(drop_loss, recovery_gain)

    def test_zero_alignment_force_veto(self):
        """Verify complete metric collapse immediately revokes authorization."""
        authorized, state = self.engine.evaluate_state(current_alignment=0.0)
        self.assertFalse(authorized)
        self.assertEqual(state["trust"], 0.0)

if __name__ == "__main__":
    unittest.main()
