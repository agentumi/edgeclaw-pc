#!/usr/bin/env bash
# EdgeClaw EVM — Sepolia Testnet Deployment
#
# Prerequisites:
#   1. Node.js 18+ installed
#   2. cd contracts/evm && npm install
#   3. Set environment variables:
#      export SEPOLIA_RPC_URL="https://sepolia.infura.io/v3/YOUR_KEY"
#        or use Alchemy: "https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY"
#      export PRIVATE_KEY="0xYOUR_DEPLOYER_PRIVATE_KEY"
#   4. Get Sepolia ETH from faucet:
#      https://sepoliafaucet.com/ or https://www.alchemy.com/faucets/ethereum-sepolia
#
# Usage:
#   chmod +x scripts/deploy-sepolia.sh
#   ./scripts/deploy-sepolia.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_DIR="$(dirname "$SCRIPT_DIR")"

echo "═══════════════════════════════════════════════════════════"
echo "  EdgeClaw EVM — Sepolia Testnet Deployment"
echo "═══════════════════════════════════════════════════════════"

# ─── Preflight ──────────────────────────────────────────

echo ""
echo "[1/4] Preflight checks..."

if ! command -v node &>/dev/null; then
    echo "ERROR: Node.js not found. Install from https://nodejs.org/"
    exit 1
fi
echo "  Node.js: $(node --version)"

if [[ -z "${SEPOLIA_RPC_URL:-}" ]]; then
    echo "ERROR: SEPOLIA_RPC_URL not set."
    echo "  export SEPOLIA_RPC_URL=\"https://sepolia.infura.io/v3/YOUR_KEY\""
    exit 1
fi
echo "  RPC URL: ${SEPOLIA_RPC_URL:0:40}..."

if [[ -z "${PRIVATE_KEY:-}" ]]; then
    echo "ERROR: PRIVATE_KEY not set."
    echo "  export PRIVATE_KEY=\"0xYOUR_DEPLOYER_PRIVATE_KEY\""
    exit 1
fi
echo "  Private key: ${PRIVATE_KEY:0:6}...${PRIVATE_KEY: -4}"

# ─── Install ───────────────────────────────────────────

cd "$CONTRACT_DIR"

if [[ ! -d "node_modules" ]]; then
    echo ""
    echo "[2/4] Installing dependencies..."
    npm install
else
    echo ""
    echo "[2/4] Dependencies already installed."
fi

# ─── Compile + Test ─────────────────────────────────────

echo ""
echo "[3/4] Compiling & testing contracts..."
npx hardhat compile
npx hardhat test

# ─── Deploy ─────────────────────────────────────────────

echo ""
echo "[4/4] Deploying to Sepolia..."
npx hardhat run scripts/deploy.js --network sepolia

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Deployment complete!"
echo "  Verify on Etherscan: https://sepolia.etherscan.io/"
echo "═══════════════════════════════════════════════════════════"
