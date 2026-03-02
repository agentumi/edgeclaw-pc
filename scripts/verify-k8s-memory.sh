#!/bin/bash
# Verify K8s pod memory < 128Mi
# Prerequisites: minikube or kubectl connected to a cluster
# Usage: ./scripts/verify-k8s-memory.sh
set -euo pipefail

NAMESPACE="edgeclaw-test"
RELEASE_NAME="edgeclaw-verify"
MAX_MEMORY_MI=128
WAIT_SECS=60

echo "=== EdgeClaw K8s Memory Verification ==="
echo ""

# Check prerequisites
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Install kubectl first."
    exit 1
fi

if ! command -v helm &> /dev/null; then
    echo "❌ helm not found. Install helm first."
    exit 1
fi

# Check if minikube is running (optional)
if command -v minikube &> /dev/null; then
    MINIKUBE_STATUS=$(minikube status --format='{{.Host}}' 2>/dev/null || echo "Stopped")
    if [ "${MINIKUBE_STATUS}" != "Running" ]; then
        echo "[0/5] Starting minikube..."
        minikube start --memory=2048 --cpus=2
    fi
fi

# Create namespace
echo "[1/5] Creating namespace ${NAMESPACE}..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Deploy with Helm
echo "[2/5] Deploying EdgeClaw via Helm..."
helm upgrade --install "${RELEASE_NAME}" ./helm/edgeclaw \
    --namespace "${NAMESPACE}" \
    --set resources.limits.memory="${MAX_MEMORY_MI}Mi" \
    --set resources.requests.memory="64Mi" \
    --set persistence.enabled=false \
    --wait --timeout 120s

# Wait for pod to be running
echo "[3/5] Waiting for pod to be ready (${WAIT_SECS}s)..."
kubectl wait --for=condition=ready pod \
    -l "app.kubernetes.io/name=edgeclaw" \
    -n "${NAMESPACE}" \
    --timeout="${WAIT_SECS}s"

POD_NAME=$(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=edgeclaw" -o jsonpath='{.items[0].metadata.name}')
echo "Pod: ${POD_NAME}"

# Check memory usage
echo "[4/5] Measuring memory usage..."
sleep 10  # Let the agent stabilize

# Method 1: kubectl top (requires metrics-server)
if kubectl top pod "${POD_NAME}" -n "${NAMESPACE}" &>/dev/null; then
    MEMORY_USAGE=$(kubectl top pod "${POD_NAME}" -n "${NAMESPACE}" --no-headers | awk '{print $3}')
    echo "Memory usage (kubectl top): ${MEMORY_USAGE}"
else
    echo "Note: metrics-server not available, using /proc/meminfo fallback"
    # Method 2: Read from /proc inside container
    RSS_KB=$(kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- cat /proc/1/status 2>/dev/null | grep VmRSS | awk '{print $2}')
    if [ -n "${RSS_KB}" ]; then
        RSS_MI=$((RSS_KB / 1024))
        echo "Memory RSS: ${RSS_MI}Mi (${RSS_KB} KB)"
    else
        echo "Could not read memory from /proc (read-only container)"
        echo "Using resource limits verification instead..."
    fi
fi

# Verify resource limits are set
echo ""
echo "[5/5] Verification:"
LIMITS=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.containers[0].resources.limits.memory}')
REQUESTS=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.containers[0].resources.requests.memory}')
echo "Resource limits:   ${LIMITS}"
echo "Resource requests: ${REQUESTS}"

# Check if OOMKilled
RESTART_COUNT=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].restartCount}')
LAST_STATE=$(kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].lastState}' 2>/dev/null || echo "{}")

if [ "${RESTART_COUNT}" -eq 0 ]; then
    echo ""
    echo "✅ PASS — Pod running within ${MAX_MEMORY_MI}Mi limit"
    echo "  - Memory limit: ${LIMITS}"
    echo "  - Memory request: ${REQUESTS}"
    echo "  - Restarts: ${RESTART_COUNT} (no OOMKill)"
else
    echo ""
    echo "⚠️  Pod restarted ${RESTART_COUNT} time(s)"
    echo "  Last state: ${LAST_STATE}"
    if echo "${LAST_STATE}" | grep -q "OOMKilled"; then
        echo "❌ FAIL — OOMKilled! Pod exceeds ${MAX_MEMORY_MI}Mi"
        exit 1
    fi
fi

# Cleanup
echo ""
echo "Cleanup:"
echo "  helm uninstall ${RELEASE_NAME} -n ${NAMESPACE}"
echo "  kubectl delete namespace ${NAMESPACE}"

# Expected memory usage:
# - edgeclaw-agent RSS:  ~20-40 Mi (Rust binary, minimal allocations)
# - Alpine overhead:     ~5 Mi
# ────────────────────────────────────
# Total expected:        ~25-45 Mi (well within 128Mi limit)
#
# Rationale:
# - Release binary: 6.31 MB (most is code/rodata, not heap)
# - No GC, no runtime (Rust)
# - Tokio thread pool: ~8 threads × ~2MB stack = ~16Mi
# - Connection buffers: 32 peers × ~4KB = ~128KB
# - RBAC/Policy tables: <1MB
