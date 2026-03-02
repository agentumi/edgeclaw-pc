#!/bin/bash
# Verify Docker image size < 100MB
# Usage: ./scripts/verify-docker-size.sh
set -euo pipefail

IMAGE_NAME="edgeclaw-agent"
MAX_SIZE_MB=100

echo "=== EdgeClaw Docker Image Size Verification ==="
echo ""

# Build the image
echo "[1/3] Building Docker image..."
docker build -t "${IMAGE_NAME}:verify" . 2>&1 | tail -5
echo ""

# Get image size
echo "[2/3] Checking image size..."
SIZE_BYTES=$(docker image inspect "${IMAGE_NAME}:verify" --format='{{.Size}}')
SIZE_MB=$((SIZE_BYTES / 1024 / 1024))

echo "Image: ${IMAGE_NAME}:verify"
echo "Size: ${SIZE_MB} MB (${SIZE_BYTES} bytes)"
echo "Limit: ${MAX_SIZE_MB} MB"
echo ""

# Verify
echo "[3/3] Verification:"
if [ "${SIZE_MB}" -lt "${MAX_SIZE_MB}" ]; then
    echo "✅ PASS — Docker image ${SIZE_MB}MB < ${MAX_SIZE_MB}MB limit"
    
    # Show layer breakdown
    echo ""
    echo "Layer breakdown:"
    docker history "${IMAGE_NAME}:verify" --format "{{.Size}}\t{{.CreatedBy}}" | head -10
else
    echo "❌ FAIL — Docker image ${SIZE_MB}MB >= ${MAX_SIZE_MB}MB limit"
    echo ""
    echo "Layer breakdown (for debugging):"
    docker history "${IMAGE_NAME}:verify" --format "{{.Size}}\t{{.CreatedBy}}"
    exit 1
fi

echo ""
echo "Cleanup: docker rmi ${IMAGE_NAME}:verify"

# Expected sizes:
# - alpine:3.19 base:     ~5 MB
# - ca-certificates:      ~1 MB
# - tzdata:               ~3 MB
# - edgeclaw-agent binary: ~6 MB (stripped)
# - static/ assets:       ~1 MB
# - config:               ~1 KB
# ─────────────────────────────────
# Total estimate:         ~16 MB
