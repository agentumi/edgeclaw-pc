#!/bin/bash
source "$HOME/.cargo/env" 2>/dev/null || true
cd /mnt/d/edgeclaw_desktop

TARGETS=(
    fuzz_policy
    fuzz_message_deserialize
    fuzz_quic_frame
    fuzz_federation_policy
    fuzz_wasm_protocol
    fuzz_tee_attestation
)

echo "=== FUZZ REMAINING 6 TARGETS x 1,000,000 ===" > /mnt/d/edgeclaw_desktop/fuzz_remaining.log
echo "Start: $(date)" >> /mnt/d/edgeclaw_desktop/fuzz_remaining.log

for target in "${TARGETS[@]}"; do
    echo ">>> Running $target (1M runs)..." >> /mnt/d/edgeclaw_desktop/fuzz_remaining.log
    START_TIME=$(date +%s)
    
    if cargo +nightly fuzz run "$target" -- -runs=1000000 >> /mnt/d/edgeclaw_desktop/fuzz_remaining.log 2>&1; then
        END_TIME=$(date +%s)
        ELAPSED=$((END_TIME - START_TIME))
        echo ">>> $target PASSED (${ELAPSED}s)" >> /mnt/d/edgeclaw_desktop/fuzz_remaining.log
    else
        echo ">>> $target FAILED" >> /mnt/d/edgeclaw_desktop/fuzz_remaining.log
    fi
    echo "" >> /mnt/d/edgeclaw_desktop/fuzz_remaining.log
done

echo "=== ALL REMAINING FUZZ COMPLETE ===" >> /mnt/d/edgeclaw_desktop/fuzz_remaining.log
echo "End: $(date)" >> /mnt/d/edgeclaw_desktop/fuzz_remaining.log
