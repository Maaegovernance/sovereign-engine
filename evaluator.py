"""Semantic Policy Evaluation with Identity-Bound Council Signatures and Ledger Auditing.

Gate 3 of the Sovereign Engine pipeline:
  - Central invariant (alignment ≥ base threshold)
  - Policy-specific metric thresholds
  - Identity-bound M-of-N council signatures via CouncilRegistry
  - Cooldown / anti-flapping
  - Immutable ledger audit of every decision
"""

import time
from typing import Dict, Any, Tuple, Optional, List
from policy import PolicyRegistry, EscalationLevel
from ledger_server import LedgerServer

try:
    from council import CouncilRegistry
    _HAS_COUNCIL = True
except ImportError:
    _HAS_COUNCIL = False
    CouncilRegistry = None  # type: ignore


class PolicyEvaluator:
    def __init__(
        self,
        registry: PolicyRegistry,
        ledger: LedgerServer,
        base_alignment_threshold: float = 0.31,
        council_registry: Optional["CouncilRegistry"] = None,
        # retained for backward-compatible single-secret mode (deprecated)
        shared_secret: Optional[bytes] = None,
    ):
        self.registry = registry
        self.ledger = ledger
        self.base_alignment_threshold = base_alignment_threshold
        self.council_registry = council_registry
        self.shared_secret = shared_secret  # only used if no council_registry
        self.last_execution_timestamps: Dict[str, float] = {}

    def evaluate_command(
        self,
        policy_id: str,
        current_alignment: float,
        current_trust: float,
        requestor_id: str = "system",
        signature_map: Optional[Dict[str, str]] = None,
        # backward-compat alias
        human_signatures: Optional[List[str]] = None,
    ) -> Tuple[bool, str, EscalationLevel]:
        """Evaluate a command against invariant + policy + identity-bound council signatures.

        Preferred path: pass signature_map = {member_id: hmac_hex} together with a
        CouncilRegistry attached at construction time.
        """
        signature_map = signature_map or {}
        decision = False
        reason = ""
        escalation_level = EscalationLevel.HARD_VETO_SYSTEM_HALT

        try:
            # 1. Hard Central Security Invariant Gate
            if current_alignment < self.base_alignment_threshold:
                reason = (
                    f"HALT: Absolute alignment breach below "
                    f"{self.base_alignment_threshold} threshold."
                )
                escalation_level = EscalationLevel.HARD_VETO_SYSTEM_HALT
                return False, reason, escalation_level

            policy = self.registry.get_policy(policy_id)
            if not policy:
                reason = f"VETO: Unknown policy template {policy_id}."
                escalation_level = EscalationLevel.HARD_VETO_SYSTEM_HALT
                return False, reason, escalation_level

            escalation_level = policy.escalation_level

            # 2. Cooldown & Anti-Flapping Gate
            now = time.time()
            last_exec = self.last_execution_timestamps.get(policy_id, 0.0)
            if (now - last_exec) < policy.max_execution_frequency_sec:
                reason = f"VETO: Cooldown active for policy {policy_id}."
                return False, reason, escalation_level

            # 3. Policy Metric Gate
            if current_alignment < policy.min_alignment_required:
                reason = (
                    f"VETO: Alignment {current_alignment:.2f} insufficient for "
                    f"{policy.objective_class.value} "
                    f"(requires {policy.min_alignment_required:.2f})."
                )
                return False, reason, escalation_level

            if current_trust < policy.min_trust_required:
                reason = (
                    f"VETO: Trust {current_trust:.2f} insufficient for "
                    f"{policy.objective_class.value} "
                    f"(requires {policy.min_trust_required:.2f})."
                )
                return False, reason, escalation_level

            # 4. Identity-bound Human-in-the-Loop Gate
            if policy.required_signatures_count > 0:
                payload_str = f"{policy_id}:{requestor_id}"

                if self.council_registry is not None and _HAS_COUNCIL:
                    # Preferred path: identity-bound council verification
                    success, valid_signers, council_reason = (
                        self.council_registry.validate_multi_sig(
                            payload_str=payload_str,
                            signature_map=signature_map,
                            required_count=policy.required_signatures_count,
                        )
                    )
                    if not success:
                        reason = f"REJECTED_COUNCIL_QUORUM: {council_reason}"
                        return False, reason, escalation_level
                else:
                    # No council registry → hard reject when signatures are required
                    reason = "REJECTED_NO_COUNCIL_REGISTRY"
                    return False, reason, escalation_level

            self.last_execution_timestamps[policy_id] = now
            decision = True
            reason = "AUTHORIZED"
            return True, reason, escalation_level

        finally:
            audit_payload = {
                "event": "POLICY_EVALUATION",
                "policy_id": policy_id,
                "requestor_id": requestor_id,
                "alignment": current_alignment,
                "trust": current_trust,
                "decision": decision,
                "reason": reason,
                "escalation_level": escalation_level.value,
                "timestamp": time.time(),
            }
            self.ledger.record_transition(audit_payload)
