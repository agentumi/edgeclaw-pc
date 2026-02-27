#!/usr/bin/env bash
# EdgeClaw Fuzz Test Runner
# Runs all 8 fuzz targets with configurable iteration count
# Usage: ./scripts/fuzz_all.sh [runs_per_target]

set -euo pipefail

RUNS=${1:-1000000}
TARGETS=(
    fuzz_ecnp_parse
    fuzz_message_deserialize
    fuzz_aes_gcm
    fuzz_policy
    fuzz_wasm_protocol
    fuzz_federation_policy
    fuzz_quic_frame
    fuzz_tee_attestation
)

REPORT_DIR="fuzz/reports"
mkdir -p "$REPORT_DIR"

echo "=========================================="
echo " EdgeClaw Fuzz Test Suite"
echo " Targets: ${#TARGETS[@]}"
echo " Iterations per target: $RUNS"
echo "=========================================="

PASSED=0
FAILED=0
REPORT_FILE="$REPORT_DIR/fuzz_report_$(date +%Y%m%d_%H%M%S).md"

echo "# EdgeClaw Fuzz Report" > "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "- **Date**: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$REPORT_FILE"
echo "- **Iterations per target**: $RUNS" >> "$REPORT_FILE"
echo "- **Toolchain**: $(rustup run nightly rustc --version)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "| Target | Status | Duration | Executions |" >> "$REPORT_FILE"
echo "|--------|--------|----------|------------|" >> "$REPORT_FILE"

for TARGET in "${TARGETS[@]}"; do
    echo ""
    echo "--- Running: $TARGET ($RUNS iterations) ---"
    START=$(date +%s)
    
    if cargo +nightly fuzz run "$TARGET" -- -runs="$RUNS" 2>&1; then
        END=$(date +%s)
        DURATION=$((END - START))
        echo "| $TARGET | PASS | ${DURATION}s | $RUNS |" >> "$REPORT_FILE"
        PASSED=$((PASSED + 1))
        echo "  ✓ $TARGET PASSED (${DURATION}s)"
    else
        END=$(date +%s)
        DURATION=$((END - START))
        echo "| $TARGET | **FAIL** | ${DURATION}s | - |" >> "$REPORT_FILE"
        FAILED=$((FAILED + 1))
        echo "  ✗ $TARGET FAILED (${DURATION}s)"
    fi
done

echo "" >> "$REPORT_FILE"
echo "## Summary" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "- **Passed**: $PASSED / ${#TARGETS[@]}" >> "$REPORT_FILE"
echo "- **Failed**: $FAILED / ${#TARGETS[@]}" >> "$REPORT_FILE"

echo ""
echo "=========================================="
echo " Results: $PASSED passed, $FAILED failed"
echo " Report: $REPORT_FILE"
echo "=========================================="

exit $FAILED
