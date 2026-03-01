#!/usr/bin/env bash
# EdgeClaw SUI Move — Testnet Deployment Script
#
# Prerequisites:
#   1. Install SUI CLI:
#      cargo install --locked --git https://github.com/MystenLabs/sui.git --branch testnet sui
#
#   2. Configure testnet:
#      sui client new-env --alias testnet --rpc https://fullnode.testnet.sui.io:443
#      sui client switch --env testnet
#
#   3. Generate keypair (if needed):
#      sui client new-address ed25519
#
#   4. Get testnet SUI (gas):
#      sui client faucet
#
# Usage:
#   chmod +x scripts/deploy-testnet.sh
#   ./scripts/deploy-testnet.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_DIR="$(dirname "$SCRIPT_DIR")"
GAS_BUDGET="${GAS_BUDGET:-200000000}"

echo "═══════════════════════════════════════════════════════════"
echo "  EdgeClaw SUI Move — Testnet Deployment"
echo "═══════════════════════════════════════════════════════════"

# ─── Preflight Checks ──────────────────────────────────

echo ""
echo "[1/5] Preflight checks..."

if ! command -v sui &>/dev/null; then
    echo "ERROR: 'sui' CLI not found."
    echo "Install: cargo install --locked --git https://github.com/MystenLabs/sui.git --branch testnet sui"
    exit 1
fi

SUI_VERSION=$(sui --version 2>&1 || true)
echo "  SUI CLI: $SUI_VERSION"

ACTIVE_ENV=$(sui client active-env 2>&1 || echo "unknown")
echo "  Active env: $ACTIVE_ENV"

ACTIVE_ADDR=$(sui client active-address 2>&1 || echo "none")
echo "  Active address: $ACTIVE_ADDR"

if [[ "$ACTIVE_ADDR" == "none" ]]; then
    echo ""
    echo "No active address. Creating new ed25519 keypair..."
    sui client new-address ed25519
    ACTIVE_ADDR=$(sui client active-address)
    echo "  New address: $ACTIVE_ADDR"
fi

# Check balance
echo ""
echo "[2/5] Checking balance..."
BALANCE=$(sui client gas 2>&1 || echo "0")
echo "$BALANCE"

if echo "$BALANCE" | grep -q "No gas coins"; then
    echo ""
    echo "No gas coins found. Requesting from faucet..."
    sui client faucet
    echo "Waiting 5s for faucet tx..."
    sleep 5
    sui client gas
fi

# ─── Build ──────────────────────────────────────────────

echo ""
echo "[3/5] Building Move contracts..."
cd "$CONTRACT_DIR"
sui move build

# ─── Test ───────────────────────────────────────────────

echo ""
echo "[4/5] Running Move tests..."
sui move test

# ─── Deploy ─────────────────────────────────────────────

echo ""
echo "[5/5] Publishing to testnet (gas budget: $GAS_BUDGET)..."
echo ""

PUBLISH_OUTPUT=$(sui client publish --gas-budget "$GAS_BUDGET" --json 2>&1)

# Parse output
if echo "$PUBLISH_OUTPUT" | grep -q '"status":"success"'; then
    echo "✅ Deployment SUCCESSFUL!"
    echo ""

    # Extract package ID
    PACKAGE_ID=$(echo "$PUBLISH_OUTPUT" | grep -o '"packageId":"[^"]*"' | head -1 | cut -d'"' -f4)
    echo "  Package ID:  $PACKAGE_ID"

    # Extract created objects
    echo ""
    echo "  Created Objects:"
    echo "$PUBLISH_OUTPUT" | grep -o '"objectId":"[^"]*"' | while read -r line; do
        OBJ_ID=$(echo "$line" | cut -d'"' -f4)
        echo "    - $OBJ_ID"
    done

    # Save deployment info
    DEPLOY_FILE="$CONTRACT_DIR/deployment-testnet.json"
    cat > "$DEPLOY_FILE" <<EOF
{
  "network": "testnet",
  "rpc": "https://fullnode.testnet.sui.io:443",
  "deployer": "$ACTIVE_ADDR",
  "package_id": "$PACKAGE_ID",
  "gas_budget": $GAS_BUDGET,
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "sui_version": "$SUI_VERSION",
  "modules": [
    "device_registry",
    "policy_nft",
    "task_token",
    "audit_anchor"
  ]
}
EOF
    echo ""
    echo "  Deployment info saved: $DEPLOY_FILE"
else
    echo "❌ Deployment FAILED!"
    echo ""
    echo "$PUBLISH_OUTPUT"
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Deployment complete!"
echo "  Explorer: https://suiexplorer.com/object/$PACKAGE_ID?network=testnet"
echo "═══════════════════════════════════════════════════════════"
