#!/bin/bash
# Fuzz all 8 targets with 1,000,000 runs each
set -e

cd /mnt/d/edgeclaw_desktop

TARGETS=(
    fuzz_ecnp_parse
    fuzz_aes_gcm
    fuzz_policy
    fuzz_message_deserialize
    fuzz_quic_frame
    fuzz_federation_policy
    fuzz_wasm_protocol
    fuzz_tee_attestation
)

TOTAL=0
PASSED=0
FAILED=0

echo "=== FUZZ ALL 8 TARGETS x 1,000,000 ==="
echo "Start: $(date)"
echo ""

for target in "${TARGETS[@]}"; do
    echo ">>> Running $target (1M runs)..."
    START_TIME=$(date +%s)
    
    if cargo +nightly fuzz run "$target" -- -runs=1000000 2>&1 | tail -3; then
        END_TIME=$(date +%s)
        ELAPSED=$((END_TIME - START_TIME))
        echo ">>> $target PASSED (${ELAPSED}s)"
        PASSED=$((PASSED + 1))
    else
        echo ">>> $target FAILED"
        FAILED=$((FAILED + 1))
    fi
    
    TOTAL=$((TOTAL + 1))
    echo ""
done

echo "=== FUZZ RESULTS ==="
echo "Total: $TOTAL targets"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "Total runs: 8,000,000 (8 targets x 1,000,000)"
echo "End: $(date)"
echo "=== ALL FUZZ COMPLETE ==="
