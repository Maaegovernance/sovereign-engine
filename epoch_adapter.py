"""Epoch Adapter: Coordinates synchronized sampling across Sensor, Governance, and Ledger components."""

from typing import Dict, Any
from governance import GovernanceEngine
from sensor_node import SensorNode
from ledger_server import LedgerServer

class EpochAdapter:
    def __init__(self, governance: GovernanceEngine, sensor: SensorNode, ledger: LedgerServer):
        self.governance = governance
        self.sensor = sensor
        self.ledger = ledger

    def step_epoch(self, noise_level: float = 0.02) -> Dict[str, Any]:
        """Executes a single synchronized state loop across the system graph."""
        # 1. Sample metric from sensor node
        alignment_sample = self.sensor.sample_alignment_metric(noise_level=noise_level)
        
        # 2. Evaluate invariant via governance engine
        authorized, state_payload = self.governance.evaluate_state(alignment_sample)
        
        # 3. Commit state transition to cryptographically immutable ledger
        block_hash = self.ledger.record_transition(state_payload)
        state_payload["block_hash"] = block_hash
        
        return state_payload
