#!/usr/bin/env bash
# deploy_mesh.sh
# Multi-Node Cluster Orchestration and Fault Injection Harness
# Incorporates: explicit quorum math, Byzantine vote suppression, ledger fork detection

set -e

echo "=== Sovereign Engine: Distributed Mesh Deployment Pipeline ==="

# 1. Verify Test Environment
echo "[1/4] Executing unit test suite..."
python3 -m unittest test_consensus.py test_governance.py test_actuation.py -v

# 2. Execute 3-Node Cluster Simulation
echo "[2/4] Initializing 3-Node Cluster Simulation..."
python3 -c "
from network_node import NetworkNode
from consensus_engine import ConsensusEngine

print('Setting up 3-node mesh topology...')
nodes = [
    NetworkNode('node-01', initial_trust=0.6),
    NetworkNode('node-02', initial_trust=0.6),
    NetworkNode('node-03', initial_trust=0.6),
]
engine = ConsensusEngine(nodes, quorum_fraction=0.67, min_online=2)

# Scenario A: Healthy Epoch
print('Running Healthy Consensus Round...')
for n in nodes:
    n.force_alignment(0.85)
result = engine.run_consensus_round(proposal={'action': 'HEALTHY_DISPATCH'})
print(f'  Decision: {result[\"decision\"]} | YES: {result[\"yes_count\"]}/{result[\"online_count\"]} (required {result[\"required\"]})')
assert result['decision'] == 'ACCEPT', 'Healthy quorum failed!'
print('  PASS: Healthy quorum reached')

# Scenario B: Single-Node Alignment Breach
print('Injecting alignment breach into node-03...')
nodes[0].force_alignment(0.80)
nodes[1].force_alignment(0.82)
nodes[2].force_alignment(0.20)  # below 0.31 threshold
result_breach = engine.run_consensus_round(proposal={'action': 'BREACH_ATTEMPT'})
print(f'  Decision: {result_breach[\"decision\"]} | Votes: {[v[\"vote\"] for v in result_breach[\"votes\"]]}')
assert result_breach['decision'] == 'REJECT', 'Breach scenario should have been rejected!'
# Explicit check that the breached node voted NO
breached_vote = next(v for v in result_breach['votes'] if v['node_id'] == 'node-03')
assert breached_vote['vote'] == 'NO', 'CRITICAL: Breached node was allowed to vote YES!'
print('  PASS: Breached node correctly suppressed')
"

# 3. Execute 7-Node Cluster Simulation with Byzantine & Fault Scenarios
echo "[3/4] Initializing 7-Node Cluster Simulation with Fault Injection..."
python3 -c "
from network_node import NetworkNode
from consensus_engine import ConsensusEngine

print('Setting up 7-node mesh topology...')
nodes = [NetworkNode(f'node-0{i}', initial_trust=0.7) for i in range(1, 8)]
engine = ConsensusEngine(nodes, quorum_fraction=0.67, min_online=3)

total_nodes = len(nodes)
# Explicit quorum math (ceil of 2/3)
required = max(1, int(total_nodes * 0.67 + 0.999))
print(f'  Quorum math: {total_nodes} nodes → required YES votes = {required}')

# Fault Pattern 1: Transient Offline (Nodes 6 & 7 drop offline)
print('Fault Injection 1: Silent/Offline Nodes...')
for n in nodes:
    n.force_alignment(0.88)
engine.inject_fault('node-06', offline=True)
engine.inject_fault('node-07', offline=True)
result_offline = engine.run_consensus_round(proposal={'action': 'OFFLINE_TEST'})
print(f'  Decision: {result_offline[\"decision\"]} | Online: {result_offline[\"online_count\"]} | YES: {result_offline[\"yes_count\"]}')
assert result_offline['online_count'] == 5, 'Expected 5 online nodes'
assert result_offline['decision'] == 'ACCEPT', 'Quorum should still pass with 5/7 online and healthy'
print('  PASS: Quorum survived 2 offline nodes')

# Bring them back for next tests
engine.inject_fault('node-06', offline=False)
engine.inject_fault('node-07', offline=False)

# Fault Pattern 2: Byzantine Telemetry Injection (low alignment, high trust attempt)
print('Fault Injection 2: Byzantine Telemetry Attempt...')
for n in nodes:
    n.force_alignment(0.85)
    n.governance.trust_score = 0.95  # artificially high trust
# Make one node Byzantine (low alignment)
nodes[3].force_alignment(0.20)
result_byz = engine.run_consensus_round(proposal={'action': 'BYZANTINE_ATTEMPT'})
byz_vote = next(v for v in result_byz['votes'] if v['node_id'] == 'node-04')
print(f'  Byzantine node vote: {byz_vote[\"vote\"]} | reason: {byz_vote.get(\"reason\", \"\")}')
assert byz_vote['vote'] == 'NO', 'CRITICAL: Byzantine node bypassed local alignment gate!'
print('  PASS: Byzantine vote correctly suppressed')

# Fault Pattern 3: Cascading Alignment Degradation
print('Fault Injection 3: Cascading Alignment Drop below 0.31...')
alignments = [0.90, 0.85, 0.80, 0.28, 0.25, 0.20, 0.15]  # 4 nodes breached
for n, a in zip(nodes, alignments):
    n.force_alignment(a)
result_cascade = engine.run_consensus_round(proposal={'action': 'CASCADE_BREACH'})
print(f'  Decision: {result_cascade[\"decision\"]} | YES votes: {result_cascade[\"yes_count\"]}/7')
assert result_cascade['decision'] == 'REJECT', 'Cascading degradation MUST veto network authorization!'
print('  PASS: Cascading breach correctly vetoed')
"

# 4. Strict Ledger Fork & Divergence Detection Verification
echo "[4/4] Verifying cryptographic ledger consistency and fork detection..."
python3 -c "
from ledger_server import LedgerServer

l1 = LedgerServer()
l2 = LedgerServer()

# Consistent Transition
payload_valid = {'epoch': 1, 'decision': 'AUTHORIZE', 'alignment': 0.85, 'voter_count': 5}
hash1 = l1.record_transition(payload_valid)
hash2 = l2.record_transition(payload_valid)

assert hash1 == hash2, 'Identical transitions produced mismatched hashes!'
print(f'  Identical payloads → matching hashes: {hash1[:12]}...')

# Simulated State Divergence / Fork
payload_divergent = {'epoch': 2, 'decision': 'VETO', 'alignment': 0.25, 'voter_count': 7}
l2.record_transition(payload_divergent)

# Hash mismatch must trigger fork awareness
fork_detected = l1.chain[-1]['hash'] != l2.chain[-1]['hash']
print(f'  Ledger Fork Detection: {fork_detected}')
print(f'    Chain 1 tip: {l1.chain[-1][\"hash\"][:12]}...')
print(f'    Chain 2 tip: {l2.chain[-1][\"hash\"][:12]}...')
assert fork_detected, 'Divergent state transitions failed to create a detectable fork!'
print('  PASS: Fork correctly detected')
"

echo ""
echo "=== Distributed Mesh Deployment & Fault Verification Complete ==="
echo "All checks passed:"
echo "  • Unit tests"
echo "  • 3-node healthy + breach scenarios"
echo "  • 7-node offline / Byzantine / cascading fault injection"
echo "  • Ledger fork detection"
