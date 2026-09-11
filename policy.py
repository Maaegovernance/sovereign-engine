"""Sovereign Semantics & Policy Definition Engine."""

from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


class ObjectiveClass(Enum):
    READ_ONLY = "READ_ONLY"              # Zero system state impact
    LOW_RISK_ACTUATION = "LOW_RISK"      # Reversible local parameter tuning
    HIGH_RISK_ACTUATION = "HIGH_RISK"    # Irreversible infrastructure/state changes
    CRITICAL_INFRASTRUCTURE = "CRITICAL" # System-level safety override / global actions


class EscalationLevel(Enum):
    AUTOMATED = "AUTOMATED"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    MULTI_SIGN_HUMAN_REQUIRED = "MULTI_SIGN_HUMAN_REQUIRED"
    HARD_VETO_SYSTEM_HALT = "HARD_VETO_SYSTEM_HALT"


@dataclass
class PolicyTemplate:
    policy_id: str
    objective_class: ObjectiveClass
    min_alignment_required: float
    min_trust_required: float
    escalation_level: EscalationLevel
    max_execution_frequency_sec: int
    required_signatures_count: int = 1  # Threshold for MULTI_SIGN escalation


class PolicyRegistry:
    def __init__(self):
        self._policies: Dict[str, PolicyTemplate] = {}
        self._load_default_templates()

    def _load_default_templates(self):
        self.register(PolicyTemplate(
            policy_id="POL-RO-001",
            objective_class=ObjectiveClass.READ_ONLY,
            min_alignment_required=0.31,
            min_trust_required=0.00,
            escalation_level=EscalationLevel.AUTOMATED,
            max_execution_frequency_sec=0,
            required_signatures_count=0
        ))
        self.register(PolicyTemplate(
            policy_id="POL-ACT-LOW",
            objective_class=ObjectiveClass.LOW_RISK_ACTUATION,
            min_alignment_required=0.45,
            min_trust_required=0.30,
            escalation_level=EscalationLevel.AUTOMATED,
            max_execution_frequency_sec=10,
            required_signatures_count=0
        ))
        self.register(PolicyTemplate(
            policy_id="POL-ACT-HIGH",
            objective_class=ObjectiveClass.HIGH_RISK_ACTUATION,
            min_alignment_required=0.65,
            min_trust_required=0.60,
            escalation_level=EscalationLevel.HUMAN_APPROVAL_REQUIRED,
            max_execution_frequency_sec=60,
            required_signatures_count=1
        ))
        self.register(PolicyTemplate(
            policy_id="POL-CRIT-001",
            objective_class=ObjectiveClass.CRITICAL_INFRASTRUCTURE,
            min_alignment_required=0.85,
            min_trust_required=0.80,
            escalation_level=EscalationLevel.MULTI_SIGN_HUMAN_REQUIRED,
            max_execution_frequency_sec=300,
            required_signatures_count=2  # M-of-N requirement (2 signatures minimum)
        ))

    def register(self, template: PolicyTemplate):
        self._policies[template.policy_id] = template

    def get_policy(self, policy_id: str) -> Optional[PolicyTemplate]:
        return self._policies.get(policy_id)
