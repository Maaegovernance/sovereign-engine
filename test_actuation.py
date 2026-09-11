"""Unit + integration tests for ActuationController with priority queue and ledger feedback."""

import unittest
from governance import GovernanceEngine
from ledger_server import LedgerServer
from actuation import ActuationController
from priority import PriorityResolver
from policy import ObjectiveClass


class TestActuationController(unittest.TestCase):
    def setUp(self):
        self.gov = GovernanceEngine(alignment_threshold=0.31)
        self.ledger = LedgerServer()
        self.actuator = ActuationController(self.gov, self.ledger)

    # ------------------------------------------------------------------
    # Legacy single-action tests (backward compatible)
    # ------------------------------------------------------------------
    def test_actuation_blocked_on_breach(self):
        result = self.actuator.execute_action(
            action_id="ACT-001",
            action_payload={"command": "DISPATCH_SIGNAL"},
            current_alignment=0.25,
        )
        self.assertFalse(result["executed"])
        self.assertIn("vetoed", result["reason"].lower())

    def test_actuation_permitted_when_aligned(self):
        result = self.actuator.execute_action(
            action_id="ACT-002",
            action_payload={"command": "DISPATCH_SIGNAL"},
            current_alignment=0.85,
        )
        self.assertTrue(result["executed"])
        self.assertIn("successfully", result["reason"].lower())

    # ------------------------------------------------------------------
    # Priority-queue + ledger integration tests
    # ------------------------------------------------------------------
    def test_priority_queue_execution_and_ledger_feedback(self):
        raw_commands = [
            {
                "command_id": "CMD_READ",
                "objective_class": ObjectiveClass.READ_ONLY,
                "timestamp": 1000.0,
                "policy_id": "POL_READ",
                "alignment": 0.80,
            },
            {
                "command_id": "CMD_CRITICAL",
                "objective_class": ObjectiveClass.CRITICAL_INFRASTRUCTURE,
                "timestamp": 1001.0,
                "policy_id": "POL_CRIT",
                "alignment": 0.90,
            },
        ]

        ordered = PriorityResolver.resolve_contention(raw_commands)
        results = self.actuator.process_priority_queue(ordered)

        # CRITICAL must execute first
        self.assertEqual(results[0]["command_id"], "CMD_CRITICAL")
        self.assertEqual(results[0]["status"], "SUCCESS")
        self.assertEqual(results[1]["command_id"], "CMD_READ")
        self.assertEqual(results[1]["status"], "SUCCESS")

        # Both outcomes written to ledger (plus the genesis block)
        # genesis + 2 actuation records
        self.assertGreaterEqual(len(self.ledger.chain), 3)
        payloads = [b["payload"] for b in self.ledger.chain if b["payload"].get("event") == "ACTUATION_EXECUTION"]
        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0]["command_id"], "CMD_CRITICAL")
        self.assertEqual(payloads[1]["command_id"], "CMD_READ")

    def test_actuation_veto_written_to_ledger(self):
        command = {
            "command_id": "CMD_HIGH_RISK",
            "objective_class": ObjectiveClass.HIGH_RISK_ACTUATION,
            "timestamp": 2000.0,
            "policy_id": "POL_ACT_HIGH",
            "alignment": 0.20,  # below threshold
        }

        result = self.actuator.execute_command(command, current_alignment=0.20)

        self.assertEqual(result["status"], "VETOED")
        self.assertIn("vetoed", result["reason"].lower())

        payloads = [
            b["payload"]
            for b in self.ledger.chain
            if b["payload"].get("event") == "ACTUATION_EXECUTION"
        ]
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["status"], "VETOED")
        self.assertEqual(payloads[0]["command_id"], "CMD_HIGH_RISK")

    def test_mid_queue_veto_does_not_stop_remaining(self):
        """A veto mid-queue must still allow later commands to be attempted."""
        commands = [
            {
                "command_id": "CMD_OK_1",
                "objective_class": ObjectiveClass.LOW_RISK_ACTUATION,
                "timestamp": 3000.0,
                "alignment": 0.70,
            },
            {
                "command_id": "CMD_BAD",
                "objective_class": ObjectiveClass.HIGH_RISK_ACTUATION,
                "timestamp": 3001.0,
                "alignment": 0.15,  # will be vetoed
            },
            {
                "command_id": "CMD_OK_2",
                "objective_class": ObjectiveClass.READ_ONLY,
                "timestamp": 3002.0,
                "alignment": 0.60,
            },
        ]
        ordered = PriorityResolver.resolve_contention(commands)
        results = self.actuator.process_priority_queue(ordered)

        statuses = {r["command_id"]: r["status"] for r in results}
        self.assertEqual(statuses["CMD_OK_1"], "SUCCESS")
        self.assertEqual(statuses["CMD_BAD"], "VETOED")
        self.assertEqual(statuses["CMD_OK_2"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
