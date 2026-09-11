#!/usr/bin/env bash
# deploy_node.sh
# Phase 1 Local Node Deployment and Verification Script

set -e

echo "=== Sovereign Engine: Node Deployment Pipeline ==="

# 1. Environment Verification
echo "[1/3] Checking environment runtime..."
python3 --version

# 2. Run Invariant Verification Test Suite
echo "[2/3] Executing security invariant test suite..."
python3 -m unittest test_governance.py test_actuation.py -v

# 3. Execute Verification Loop
echo "[3/3] Initializing single-node epoch test run..."
python3 -c "
from governance import GovernanceEngine
from sensor_node import SensorNode
from ledger_server import LedgerServer
from epoch_adapter import EpochAdapter

gov = GovernanceEngine(alignment_threshold=0.31)
sensor = SensorNode(node_id='node-01')
ledger = LedgerServer()
adapter = EpochAdapter(gov, sensor, ledger)

print('Executing 5 test epochs...')
for i in range(5):
    state = adapter.step_epoch()
    print(f'Epoch {state[\"epoch\"]}: Alignment={state[\"alignment\"]:.3f} | Trust={state[\"trust\"]:.3f} | Authorized={state[\"authorized\"]} | Block={state[\"block_hash\"][:10]}...')
"

echo "=== Node Deployment & Validation Complete ==="
