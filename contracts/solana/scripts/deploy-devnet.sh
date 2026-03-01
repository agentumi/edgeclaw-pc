#!/usr/bin/env bash
# EdgeClaw Solana — Devnet Deployment Script
#
# Prerequisites:
#   1. Install Solana CLI:
#      sh -c "$(curl -sSfL https://release.solana.com/stable/install)"
#
#   2. Install Anchor CLI:
#      cargo install --git https://github.com/coral-xyz/anchor avm --locked
#      avm install 0.29.0
#      avm use 0.29.0
#
#   3. Generate keypair (if needed):
#      solana-keygen new -o ~/.config/solana/id.json
#
#   4. Configure devnet:
#      solana config set --url https://api.devnet.solana.com
#
#   5. Get devnet SOL (gas):
#      solana airdrop 2
#
#   6. Install Node.js deps (for tests):
#      cd contracts/solana && yarn install
#
# Usage:
#   chmod +x scripts/deploy-devnet.sh
#   ./scripts/deploy-devnet.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_DIR="$(dirname "$SCRIPT_DIR")"

echo "═══════════════════════════════════════════════════════════"
echo "  EdgeClaw Solana — Devnet Deployment"
echo "═══════════════════════════════════════════════════════════"

# ─── Preflight ──────────────────────────────────────────

echo ""
echo "[1/5] Preflight checks..."

if ! command -v solana &>/dev/null; then
    echo "ERROR: 'solana' CLI not found."
    echo "Install: sh -c \"\$(curl -sSfL https://release.solana.com/stable/install)\""
    exit 1
fi
echo "  Solana CLI: $(solana --version)"

if ! command -v anchor &>/dev/null; then
    echo "ERROR: 'anchor' CLI not found."
    echo "Install: cargo install --git https://github.com/coral-xyz/anchor avm --locked"
    exit 1
fi
echo "  Anchor CLI: $(anchor --version)"

WALLET=$(solana address 2>/dev/null || echo "none")
echo "  Wallet: $WALLET"

if [[ "$WALLET" == "none" ]]; then
    echo ""
    echo "No wallet found. Generating new keypair..."
    solana-keygen new -o ~/.config/solana/id.json --no-bip39-passphrase
    WALLET=$(solana address)
    echo "  New wallet: $WALLET"
fi

CLUSTER=$(solana config get | grep "RPC URL" | awk '{print $NF}')
echo "  Cluster: $CLUSTER"

# ─── Switch to devnet ──────────────────────────────────

echo ""
echo "[2/5] Configuring devnet..."

if [[ "$CLUSTER" != *"devnet"* ]]; then
    solana config set --url https://api.devnet.solana.com
    echo "  Switched to devnet."
fi

# Check balance
BALANCE=$(solana balance 2>&1 || echo "0 SOL")
echo "  Balance: $BALANCE"

if echo "$BALANCE" | grep -q "^0 SOL"; then
    echo "  Requesting airdrop..."
    solana airdrop 2
    sleep 3
    echo "  New balance: $(solana balance)"
fi

# ─── Build ──────────────────────────────────────────────

cd "$CONTRACT_DIR"

echo ""
echo "[3/5] Building Anchor programs..."
anchor build

# ─── Update Program ID ─────────────────────────────────

echo ""
echo "[4/5] Extracting program ID..."
PROGRAM_ID=$(solana address -k target/deploy/edgeclaw_solana-keypair.json 2>/dev/null || echo "")

if [[ -n "$PROGRAM_ID" ]]; then
    echo "  Program ID: $PROGRAM_ID"

    # Update declare_id! in lib.rs
    sed -i "s/declare_id!(\".*\")/declare_id!(\"$PROGRAM_ID\")/" programs/edgeclaw/src/lib.rs
    echo "  Updated declare_id! in lib.rs"

    # Update Anchor.toml
    sed -i "s/edgeclaw = \".*\"/edgeclaw = \"$PROGRAM_ID\"/" Anchor.toml
    echo "  Updated Anchor.toml"

    # Rebuild with correct ID
    echo "  Rebuilding with correct program ID..."
    anchor build
fi

# ─── Deploy ─────────────────────────────────────────────

echo ""
echo "[5/5] Deploying to devnet..."
anchor deploy --provider.cluster devnet

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Deployment complete!"
echo ""
echo "  Program ID: $PROGRAM_ID"
echo "  Explorer:   https://explorer.solana.com/address/$PROGRAM_ID?cluster=devnet"
echo ""

# Save deployment info
DEPLOY_FILE="$CONTRACT_DIR/deployment-devnet.json"
cat > "$DEPLOY_FILE" <<EOF
{
  "network": "devnet",
  "rpc": "https://api.devnet.solana.com",
  "deployer": "$WALLET",
  "program_id": "$PROGRAM_ID",
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "anchor_version": "$(anchor --version)",
  "modules": [
    "device_registry",
    "policy_nft",
    "task_token",
    "audit_anchor"
  ]
}
EOF
echo "  Deployment info saved: $DEPLOY_FILE"
echo "═══════════════════════════════════════════════════════════"
