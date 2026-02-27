# Kubernetes Deployment Guide

> EdgeClaw V3.0 — Kubernetes Native Deployment

## Overview

EdgeClaw provides a Helm chart for deploying agents as Kubernetes-native
workloads with CRD support, auto-scaling, and Prometheus monitoring.

## Prerequisites

- Kubernetes 1.28+
- Helm 3.12+
- `kubectl` configured for your cluster

## Quick Start

### 1. Install via Helm

```bash
# Add repository (if published)
helm repo add edgeclaw https://charts.edgeclaw.io

# Or install from local chart
helm install edgeclaw ./helm/edgeclaw \
  --namespace edgeclaw \
  --create-namespace
```

### 2. Verify Installation

```bash
kubectl get pods -n edgeclaw
# NAME                        READY   STATUS    RESTARTS   AGE
# edgeclaw-5b7d8f9c4-x2j4m   1/1     Running   0          30s

kubectl get svc -n edgeclaw
# NAME        TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)
# edgeclaw    ClusterIP   10.96.45.12    <none>        8443,9444,9445/TCP
```

## Configuration

### values.yaml

```yaml
replicaCount: 1

image:
  repository: ghcr.io/agentumi/edgeclaw-agent
  tag: "3.0.0"
  pullPolicy: IfNotPresent

agent:
  deviceName: "edgeclaw-k8s"
  listenPort: 8443
  maxConnections: 50

security:
  policyMode: "strict"
  defaultRole: "viewer"
  sessionTimeoutSecs: 3600

webui:
  enabled: true
  port: 9444
  bind: "0.0.0.0"

resources:
  limits:
    cpu: 500m
    memory: 128Mi
  requests:
    cpu: 100m
    memory: 64Mi
```

### Scaling

Enable Horizontal Pod Autoscaler:

```yaml
autoscaling:
  enabled: true
  minReplicas: 1
  maxReplicas: 5
  targetCPUUtilizationPercentage: 80
  customMetrics:
    - name: edgeclaw_active_peers
      targetAverageValue: "10"
```

### Ingress

Expose WebUI externally:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: edgeclaw.example.com
      paths:
        - path: /
          pathType: ImplementationSpecific
  tls:
    - secretName: edgeclaw-tls
      hosts:
        - edgeclaw.example.com
```

### Monitoring

Enable Prometheus ServiceMonitor:

```yaml
monitoring:
  serviceMonitor:
    enabled: true
    interval: 30s
    labels:
      release: prometheus
```

## CRD: EdgeClawAgent

The EdgeClawAgent Custom Resource Definition enables declarative agent management:

```yaml
apiVersion: edgeclaw.io/v1
kind: EdgeClawAgent
metadata:
  name: production-agent
spec:
  profile: system
  replicas: 3
  version: "3.0.0"
  config:
    listenPort: 8443
    maxConnections: 100
  security:
    policyMode: strict
    defaultRole: viewer
  resources:
    limits:
      cpu: "1"
      memory: 256Mi
```

### Status

```bash
kubectl get edgeclawagents
# NAME               PHASE     READY   VERSION
# production-agent   Running   3/3     3.0.0
```

## Helm Chart Templates

| Template | Description |
|----------|-------------|
| `deployment.yaml` | Agent Pod definition with probes |
| `service.yaml` | ECNP (8443) + WebUI (9444) + WS (9445) |
| `configmap.yaml` | agent.toml configuration |
| `secret.yaml` | Ed25519/X25519 keys + TLS certs |
| `hpa.yaml` | Auto-scaling with CPU + custom metrics |
| `ingress.yaml` | External access for WebUI |
| `servicemonitor.yaml` | Prometheus metrics scraping |
| `_helpers.tpl` | Name, labels, selector helpers |

## Helm Validation

```bash
# Lint chart
helm lint ./helm/edgeclaw

# Dry-run install
helm install edgeclaw ./helm/edgeclaw --dry-run

# Template rendering
helm template edgeclaw ./helm/edgeclaw
```

## Docker Image

```dockerfile
FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/edgeclaw-agent /usr/local/bin/
EXPOSE 8443 9444 9445
ENTRYPOINT ["edgeclaw-agent"]
CMD ["start"]
```

Build and push:

```bash
docker build -t ghcr.io/agentumi/edgeclaw-agent:3.0.0 .
docker push ghcr.io/agentumi/edgeclaw-agent:3.0.0
```

## Troubleshooting

| Issue | Cause | Resolution |
|-------|-------|------------|
| Pod CrashLoopBackoff | Missing config | Ensure ConfigMap is mounted |
| Readiness probe failing | WebUI not started | Check `webui.enabled: true` |
| HPA not scaling | Missing metrics-server | Install metrics-server |
| ServiceMonitor not scraped | Label mismatch | Match Prometheus operator labels |
