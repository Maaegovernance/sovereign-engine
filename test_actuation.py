"""Unit tests verifying Actuation Controller veto enforcement and state snapshot integrity."""

import unittest
from governance import GovernanceEngine
from actuation import ActuationController

class TestActuationController(unittest.TestCase):
    def setUp(self):
        self.governance = GovernanceEngine(alignment_threshold=0.31)
        self.actuation = ActuationController(self.governance)

    def test_actuation_blocked_on_breach(self):
        """Ensure downstream actuation is halted when governance returns unauthorized."""
        result = self.actuation.execute_action(
            action_id="ACT-001",
            action_payload={"command": "DISPATCH_SIGNAL"},
            current_alignment=0.25
        )
        self.assertFalse(result["executed"])
        self.assertIn("vetoed", result["reason"].lower())

    def test_actuation_permitted_when_aligned(self):
        """Ensure actuation executes when alignment and trust meet invariant requirements."""
        result = self.actuation.execute_action(
            action_id="ACT-002",
            action_payload={"command": "DISPATCH_SIGNAL"},
            current_alignment=0.85
        )
        self.assertTrue(result["executed"])
        self.assertEqual(result["reason"], "Execution authorized.")

if __name__ == "__main__":
    unittest.main()
