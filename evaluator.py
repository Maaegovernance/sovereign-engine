"""Semantic Policy Evaluation with Cryptographic Signature Verification and Ledger Auditing."""

import hmac
import hashlib
import time
from typing import Dict, Any, Tuple, Optional, List
from policy import PolicyRegistry, ObjectiveClass, EscalationLevel
from ledger_server import LedgerServer


class PolicyEvaluator:
    def __init__(
        self,
        registry: PolicyRegistry,
        ledger: LedgerServer,
        shared_secret: bytes,
        base_alignment_threshold: float = 0.31
    ):
        self.registry = registry
        self.ledger = ledger
        self.shared_secret = shared_secret
        self.base_alignment_threshold = base_alignment_threshold
        self.last_execution_timestamps: Dict[str, float] = {}

    def verify_hmac_signature(self, payload_str: str, signature_hex: str) -> bool:
        """Verifies HMAC-SHA256 signature authenticity over payload."""
        if not signature_hex or not isinstance(signature_hex, str):
            return False
        expected_hmac = hmac.new(
            self.shared_secret,
            payload_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_hmac, signature_hex)

    def evaluate_command(
        self,
        policy_id: str,
        current_alignment: float,
        current_trust: float,
        human_signatures: Optional[List[str]] = None,
        requestor_id: str = "system"
    ) -> Tuple[bool, str, EscalationLevel]:
        """
        Evaluates command semantics against Central Invariant + Policy Rules.

        Data Provenance Note:
        `current_trust` is sourced directly from GovernanceEngine via ConsensusEngine.
        """
        signatures = human_signatures or []
        decision = False
        reason = ""
        escalation_level = EscalationLevel.HARD_VETO_SYSTEM_HALT

        try:
            # 1. Hard Central Security Invariant Gate
            if current_alignment < self.base_alignment_threshold:
                reason = f"HALT: Absolute alignment breach below {self.base_alignment_threshold} threshold."
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
                    f"{policy.objective_class.value} (requires {policy.min_alignment_required:.2f})."
                )
                return False, reason, escalation_level

            if current_trust < policy.min_trust_required:
                reason = (
                    f"VETO: Trust {current_trust:.2f} insufficient for "
                    f"{policy.objective_class.value} (requires {policy.min_trust_required:.2f})."
                )
                return False, reason, escalation_level

            # 4. Cryptographic Human-in-the-Loop (HITL) Gate
            if policy.escalation_level in (
                EscalationLevel.HUMAN_APPROVAL_REQUIRED,
                EscalationLevel.MULTI_SIGN_HUMAN_REQUIRED,
            ):
                if len(signatures) < policy.required_signatures_count:
                    reason = (
                        f"ESCALATE: Action requires {policy.required_signatures_count} "
                        f"signature(s), received {len(signatures)}."
                    )
                    return False, reason, escalation_level

                payload_str = f"{policy_id}:{requestor_id}"
                valid_sigs = sum(
                    1 for sig in signatures
                    if self.verify_hmac_signature(payload_str, sig)
                )

                if valid_sigs < policy.required_signatures_count:
                    reason = (
                        f"VETO: Invalid HMAC signature verification "
                        f"({valid_sigs}/{policy.required_signatures_count} valid)."
                    )
                    return False, reason, escalation_level

            self.last_execution_timestamps[policy_id] = now
            decision = True
            reason = "AUTHORIZED"
            return True, reason, escalation_level

        finally:
            # Always record the evaluation decision to the immutable ledger
            audit_payload = {
                "event": "POLICY_EVALUATION",
                "policy_id": policy_id,
                "requestor_id": requestor_id,
                "alignment": current_alignment,
                "trust": current_trust,
                "decision": decision,
                "reason": reason,
                "escalation_level": escalation_level.value,
                "timestamp": time.time()
            }
            self.ledger.record_transition(audit_payload)
