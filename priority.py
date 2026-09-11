"""Priority Baseline & Resource Contention Engine.

Orders concurrent authorized commands by ObjectiveClass weight and timestamp
so that higher-risk / higher-priority actuations preempt lower ones.
"""

from typing import List, Dict, Any
from policy import ObjectiveClass

PRIORITY_RANKS: Dict[ObjectiveClass, int] = {
    ObjectiveClass.CRITICAL_INFRASTRUCTURE: 100,
    ObjectiveClass.HIGH_RISK_ACTUATION: 75,
    ObjectiveClass.LOW_RISK_ACTUATION: 50,
    ObjectiveClass.READ_ONLY: 10,
}


class PriorityResolver:
    @staticmethod
    def rank_of(objective_class) -> int:
        if isinstance(objective_class, ObjectiveClass):
            return PRIORITY_RANKS.get(objective_class, 0)
        # Allow string form for convenience
        try:
            return PRIORITY_RANKS.get(ObjectiveClass(objective_class), 0)
        except (ValueError, KeyError):
            return 0

    @staticmethod
    def resolve_contention(commands: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort pending commands by ObjectiveClass rank (desc) then timestamp (desc).

        Higher-rank objective classes execute first. Within the same rank,
        newer timestamps take precedence.
        """
        return sorted(
            commands,
            key=lambda c: (
                PriorityResolver.rank_of(c.get("objective_class")),
                c.get("timestamp", 0.0),
            ),
            reverse=True,
        )
