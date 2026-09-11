"""Core governance state engine implementing invariant checks and TAIP safety gates."""

import math
import time
from typing import Dict, Any, Tuple

class GovernanceEngine:
    def __init__(self, alignment_threshold: float = 0.31, trust_decay_rate: float = 0.05):
        self.alignment_threshold = alignment_threshold
        self.trust_decay_rate = trust_decay_rate
        self.trust_score = 0.5
        self.last_alignment = 1.0
        self.epoch = 0

    def evaluate_state(self, current_alignment: float) -> Tuple[bool, Dict[str, Any]]:
        """Evaluates system state against the Central Security Invariant."""
        self.epoch += 1
        
        # Invariant: Low/degrading alignment MUST suppress trust escalation
        if current_alignment < self.alignment_threshold:
            # Force trust damping upon phase-transition breach
            self.trust_score = max(0.0, self.trust_score - self.trust_decay_rate * 2)
            authorized = False
            status = "HALT_ALIGNMENT_BREACH"
        else:
            # Objective-coupled trust update
            delta_alignment = current_alignment - self.last_alignment
            if delta_alignment < 0:
                # Critical slowing down / negative drift protection
                self.trust_score = max(0.0, self.trust_score + delta_alignment)
            else:
                self.trust_score = min(1.0, self.trust_score + (delta_alignment * 0.1))
            
            authorized = self.trust_score >= 0.2
            status = "OPERATIONAL"

        self.last_alignment = current_alignment
        
        payload = {
            "epoch": self.epoch,
            "alignment": current_alignment,
            "trust": self.trust_score,
            "status": status,
            "authorized": authorized,
            "timestamp": time.time()
        }
        return authorized, payload
