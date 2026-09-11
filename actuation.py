"""Actuation controller executing state changes strictly under governance approval."""

from typing import Dict, Any

class ActuationController:
    def __init__(self, governance_engine):
        self.governance = governance_engine
        self.execution_log = []

    def execute_action(self, action_id: str, action_payload: Dict[str, Any], current_alignment: float) -> Dict[str, Any]:
        """Validates invariant state prior to executing downstream actuation."""
        authorized, state = self.governance.evaluate_state(current_alignment)
        
        if not authorized:
            result = {
                "action_id": action_id,
                "executed": False,
                "reason": f"Execution vetoed by Governance Engine. Status: {state['status']}",
                "state_snapshot": state
            }
        else:
            result = {
                "action_id": action_id,
                "executed": True,
                "reason": "Execution authorized.",
                "state_snapshot": state
            }
            
        self.execution_log.append(result)
        return result
