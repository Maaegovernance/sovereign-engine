"""Sensor node interface monitoring metric trajectories and detecting critical slowing down."""

import random
from typing import List

class SensorNode:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.history: List[float] = []

    def sample_alignment_metric(self, noise_level: float = 0.02) -> float:
        """Simulates alignment observation with synthetic sensor variance."""
        if not self.history:
            base_val = 0.85
        else:
            base_val = self.history[-1]
            
        # Add random walk drift
        drift = random.uniform(-0.05, 0.04)
        sample = max(0.0, min(1.0, base_val + drift + random.gauss(0, noise_level)))
        self.history.append(sample)
        return sample

    def compute_variance_window(self, window_size: int = 5) -> float:
        """Calculates rolling variance as an early warning for critical slowing down."""
        if len(self.history) < window_size:
            return 0.0
        recent = self.history[-window_size:]
        mean = sum(recent) / window_size
        return sum((x - mean) ** 2 for x in recent) / window_size
