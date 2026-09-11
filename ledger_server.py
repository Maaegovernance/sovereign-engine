"""Immutable ledger server interface recording governance state transitions."""

import hashlib
import json
import time
from typing import Dict, Any, List

class LedgerServer:
    def __init__(self):
        self.chain: List[Dict[str, Any]] = []
        self._create_block(previous_hash="0", payload={"genesis": True})

    def _create_block(self, previous_hash: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "payload": payload,
            "previous_hash": previous_hash
        }
        block["hash"] = self._hash_block(block)
        self.chain.append(block)
        return block

    @staticmethod
    def _hash_block(block: Dict[str, Any]) -> str:
        block_string = json.dumps({k: block[k] for k in sorted(block) if k != "hash"}, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def record_transition(self, state_payload: Dict[str, Any]) -> str:
        """Appends a new governance snapshot to the immutable ledger."""
        prev_hash = self.chain[-1]["hash"] if self.chain else "0"
        new_block = self._create_block(previous_hash=prev_hash, payload=state_payload)
        return new_block["hash"]
