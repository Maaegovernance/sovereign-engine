"""Invariants-Gated Actuation Controller with Ledger Audit Integration.

Final execution gate of the Sovereign Engine pipeline:
  1. Receive priority-ordered command queue from ConsensusEngine
  2. Re-check local governance invariant (alignment ≥ threshold)
  3. Dispatch or veto
  4. Write every outcome to the immutable ledger
"""

import time
from typing import Dict, Any, List, Optional
from governance import GovernanceEngine
from ledger_server import LedgerServer


class ActuationController:
    def __init__(
        self,
        governance_engine: GovernanceEngine,
        ledger_server: Optional[LedgerServer] = None,
    ):
        self.governance = governance_engine
        self.ledger = ledger_server
        self.execution_log: List[Dict[str, Any]] = []

    def execute_command(
        self,
        command: Dict[str, Any],
        current_alignment: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Execute a single actuation command subject to a final invariant check.

        If current_alignment is supplied it is evaluated through GovernanceEngine.
        Otherwise the engine's last known alignment is used.
        """
        cmd_id = command.get("command_id", command.get("id", "CMD_UNKNOWN"))
        policy_id = command.get("policy_id", "POL_UNKNOWN")
        actuation_type = command.get(
            "actuation_type",
            command.get("objective_class", "GENERIC_ACTUATION"),
        )
        if hasattr(actuation_type, "value"):
            actuation_type = actuation_type.value

        # Final physical / invariant veto gate
        if current_alignment is not None:
            authorized, state = self.governance.evaluate_state(current_alignment)
        else:
            # Re-evaluate using the last recorded alignment if available
            last = getattr(self.governance, "last_alignment", 1.0)
            authorized, state = self.governance.evaluate_state(last)

        if not authorized:
            status = "VETOED"
            reason = (
                f"Actuation vetoed by Governance Engine. "
                f"Status: {state.get('status', 'UNKNOWN')}"
            )
        else:
            status = "SUCCESS"
            reason = "Actuation executed successfully within safety bounds."

        audit_entry = {
            "event": "ACTUATION_EXECUTION",
            "command_id": cmd_id,
            "policy_id": policy_id,
            "actuation_type": str(actuation_type),
            "status": status,
            "reason": reason,
            "alignment": state.get("alignment"),
            "trust": state.get("trust"),
            "timestamp": time.time(),
        }

        if self.ledger is not None:
            self.ledger.record_transition(audit_entry)

        self.execution_log.append(audit_entry)
        return audit_entry

    def process_priority_queue(
        self,
        ordered_commands: List[Dict[str, Any]],
        current_alignment: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Process an ordered batch from PriorityResolver sequentially.

        Each command is subjected to a fresh invariant check. A mid-queue
        veto does not stop the remainder of the queue; every outcome is logged.
        """
        results = []
        for cmd in ordered_commands:
            # Allow per-command alignment override if present
            align = cmd.get("alignment", current_alignment)
            result = self.execute_command(cmd, current_alignment=align)
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Backward-compatible single-action API (used by earlier tests)
    # ------------------------------------------------------------------
    def execute_action(
        self,
        action_id: str,
        action_payload: Dict[str, Any],
        current_alignment: float,
    ) -> Dict[str, Any]:
        """Legacy single-action entry point."""
        command = {
            "command_id": action_id,
            "policy_id": action_payload.get("policy_id", "POL_UNKNOWN"),
            "actuation_type": action_payload.get("command", "GENERIC"),
            **action_payload,
        }
        result = self.execute_command(command, current_alignment=current_alignment)
        # Shape expected by older tests
        return {
            "action_id": action_id,
            "executed": result["status"] == "SUCCESS",
            "reason": result["reason"],
            "state_snapshot": {
                "alignment": result.get("alignment"),
                "trust": result.get("trust"),
                "status": result["status"],
            },
        }
