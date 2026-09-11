"""Tests for Priority Baseline & Resource Contention Resolver."""

import unittest
from policy import ObjectiveClass
from priority import PriorityResolver, PRIORITY_RANKS


class TestPriorityResolver(unittest.TestCase):
    def test_critical_outranks_high_risk(self):
        commands = [
            {"id": "A", "objective_class": ObjectiveClass.HIGH_RISK_ACTUATION, "timestamp": 100.0},
            {"id": "B", "objective_class": ObjectiveClass.CRITICAL_INFRASTRUCTURE, "timestamp": 90.0},
        ]
        ordered = PriorityResolver.resolve_contention(commands)
        self.assertEqual(ordered[0]["id"], "B")
        self.assertEqual(ordered[1]["id"], "A")

    def test_same_rank_newer_timestamp_first(self):
        commands = [
            {"id": "old", "objective_class": ObjectiveClass.LOW_RISK_ACTUATION, "timestamp": 10.0},
            {"id": "new", "objective_class": ObjectiveClass.LOW_RISK_ACTUATION, "timestamp": 50.0},
        ]
        ordered = PriorityResolver.resolve_contention(commands)
        self.assertEqual(ordered[0]["id"], "new")
        self.assertEqual(ordered[1]["id"], "old")

    def test_full_ordering(self):
        commands = [
            {"id": "ro", "objective_class": ObjectiveClass.READ_ONLY, "timestamp": 200.0},
            {"id": "crit", "objective_class": ObjectiveClass.CRITICAL_INFRASTRUCTURE, "timestamp": 10.0},
            {"id": "high", "objective_class": ObjectiveClass.HIGH_RISK_ACTUATION, "timestamp": 150.0},
            {"id": "low", "objective_class": ObjectiveClass.LOW_RISK_ACTUATION, "timestamp": 180.0},
        ]
        ordered = PriorityResolver.resolve_contention(commands)
        self.assertEqual([c["id"] for c in ordered], ["crit", "high", "low", "ro"])

    def test_rank_values(self):
        self.assertGreater(
            PRIORITY_RANKS[ObjectiveClass.CRITICAL_INFRASTRUCTURE],
            PRIORITY_RANKS[ObjectiveClass.HIGH_RISK_ACTUATION],
        )
        self.assertGreater(
            PRIORITY_RANKS[ObjectiveClass.HIGH_RISK_ACTUATION],
            PRIORITY_RANKS[ObjectiveClass.LOW_RISK_ACTUATION],
        )
        self.assertGreater(
            PRIORITY_RANKS[ObjectiveClass.LOW_RISK_ACTUATION],
            PRIORITY_RANKS[ObjectiveClass.READ_ONLY],
        )


if __name__ == "__main__":
    unittest.main()
