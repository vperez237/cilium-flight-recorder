# Cilium Flight Recorder

A Go-based DaemonSet that monitors Cilium/Hubble flows for anomalies and automatically triggers targeted PCAP captures via Cilium's BPF recorder. Captured PCAPs are uploaded to S3 for post-incident analysis.

## Architecture

```mermaid
flowchart TB
    subgraph eachNode [Per-Node DaemonSet]
        HubbleClient["Hubble gRPC Client"] -->|"flow events"| Detector["Anomaly Detector"]
        ManualAPI["HTTP API :8080"] -->|"manual trigger"| CaptureManager
        Detector -->|"trigger capture"| CaptureManager["Capture Manager"]
        CaptureManager -->|"start/stop"| CiliumAPI["Cilium Agent API\n(Unix Socket)"]
        CaptureManager -->|"completed .pcap"| Uploader["S3 Uploader"]
    end

    HubbleRelay["Hubble Relay\n(cluster-wide)"] -.->|"gRPC stream"| HubbleClient
    CiliumAPI -->|"BPF recorder maps"| Datapath["Cilium eBPF Datapath"]
    Uploader -->|"PutObject"| S3["S3 Bucket"]
```

### Anomaly Triggers

| Trigger | What it detects | Flow field |
|---|---|---|
| **HTTP 5xx** | Configurable status codes (default: 500, 502, 503, 504) | `flow.l7.http.code` |
| **Packet drops** | Policy denies, conntrack issues, BPF errors | `flow.verdict == DROPPED` |
| **DNS failures** | NXDOMAIN, SERVFAIL, REFUSED | `flow.l7.dns.rcode` |
| **Latency spikes** | P99 latency exceeding a threshold (sliding window) | `flow.l7.latency_ns` |

Each trigger has a per-tuple cooldown to prevent capture storms.

### Detection Modes

HTTP errors, packet drops, and DNS failures all support two modes:

| Mode | When it fires | Best for |
|---|---|---|
| `immediate` (default) | On every matching flow | Dev/staging; rare, actionable events |
| `rate` | When the error rate exceeds a threshold over a rolling window | Production; filtering transient blips |

- **HTTP errors (`rate`)** — keyed by destination IP:port. Fires when `errors/total >= rateThreshold` and `total >= minEvents` within `windowSeconds`.
- **Drops (`rate`)** — keyed by destination IP:port. Fires when drop count `>= minDrops` within `windowSeconds`.
- **DNS failures (`rate`)** — keyed by source IP (the client making queries). Fires when `failures/total >= rateThreshold` and `total >= minEvents` within `windowSeconds`.
- **Latency** — always uses a sliding window (P99 over `windowSize` samples).

In `rate` mode, captures are scoped to the aggregated key (e.g. "any source → dst IP:port") rather than a single src/dst pair, so the PCAP shows all traffic contributing to the anomaly.

### Data Flow

1. **Hubble Relay** streams L3/L4/L7 flow events cluster-wide via gRPC
2. **Anomaly Detector** evaluates each flow against configurable rules with rate limiting
3. **Capture Manager** calls the Cilium agent REST API to start/stop the BPF recorder
4. **S3 Uploader** pushes completed PCAPs with structured keys and metadata
5. **HTTP API** exposes manual triggers and a capture listing

## Project Structure

```
cilium-flight-recorder/
  cmd/
    recorder/main.go           # Production entrypoint
    mock-cilium/main.go        # Mock Cilium agent for local dev
    mock-hubble/main.go        # Mock Hubble Relay for local dev
  pkg/
    config/config.go           # YAML config loading with defaults
    watcher/hubble.go          # Hubble gRPC client with reconnection
    detector/anomaly.go        # Rule evaluation and cooldown
    detector/rate.go           # Rolling-window error rate tracking
    capture/recorder.go        # Cilium agent API interaction
    storage/s3.go              # S3 upload with IRSA support
    api/server.go              # HTTP API for manual triggers + listing
  helm/
    Chart.yaml                 # Helm chart metadata
    values.yaml                # Default values (fully commented)
    values-example.yaml        # Per-cluster overrides (example)
    templates/                 # DaemonSet, ConfigMap, RBAC, SA, Service
  scripts/
    test-local.sh              # Comprehensive local test suite
  testdata/
    config-local.yaml          # Config for Docker-based local dev (immediate)
    config-local-rate.yaml     # Config for exercising rate-based mode
  docker-compose.yaml          # Full local environment
  Dockerfile                   # Multi-target build (prod + mocks)
  Makefile
```

## Requirements

- Go 1.25+
- Docker / Docker Compose (for local development)
- Helm 3.x (for cluster deployment)
- Cilium 1.19+ with Hubble Relay (target cluster)

## Building

```bash
# Build all binaries locally (requires Go 1.25+)
make build

# Build Docker images
make docker-build

# Run unit tests
make test
```

## Configuration

All configuration is driven by the Helm chart values. `helm/values.yaml` documents every setting inline; `helm/values-example.yaml` is the example per-cluster overlay.

### Key Helm Values

| Value | Default | Description |
|---|---|---|
| `cluster.name` | `example-cluster` | Cluster identifier (embedded in S3 keys + metadata) |
| `image.repository` | `ghcr.io/vperez237/flight-recorder` | Container image (override for your registry) |
| `image.tag` | `v<appVersion>` (e.g. `v0.1.0`) | Image tag. Empty uses the v-prefixed form of the chart's appVersion. |
| `s3.bucket` | `flight-recorder-pcaps` | Target S3 bucket |
| `s3.region` | `us-east-1` | AWS region |
| `s3.endpoint` | `""` | Custom S3 endpoint (MinIO/LocalStack) |
| `hubble.address` | `hubble-relay.kube-system.svc:4245` | Hubble Relay gRPC endpoint |
| `cilium.socketPath` | `/var/run/cilium/cilium.sock` | Node's Cilium agent socket |
| `cilium.bpfPath` | `/sys/fs/bpf` | Host BPF filesystem mount |
| `triggers.httpErrors.*` | see below | HTTP 5xx trigger |
| `triggers.drops.*` | see below | Packet drop trigger |
| `triggers.dnsFailures.*` | see below | DNS failure trigger |
| `triggers.latency.*` | see below | P99 latency trigger |
| `capture.defaultDurationSeconds` | `60` | PCAP duration for auto-captures |
| `capture.maxConcurrent` | `3` | Max concurrent captures per node |
| `capture.cooldownSeconds` | `300` | Per-tuple cooldown (prevents storms) |
| `serviceAccount.annotations` | IRSA role | Attach IRSA role ARN here |
| `resources` | 50m CPU / 128Mi req | Per-pod resource requests/limits |
| `tolerations` | `- operator: Exists` | Run on all nodes by default |
| `service.enabled` | `false` | Expose HTTP API as a ClusterIP Service |

### Trigger Values

Each trigger supports `mode: immediate` (fire on every match, default) or `mode: rate` (fire only when the error rate crosses a threshold over a rolling window):

```yaml
triggers:
  httpErrors:
    enabled: true
    statusCodes: [500, 502, 503, 504]
    mode: immediate              # or "rate"
    minEvents: 10                # rate mode: min samples per dst before evaluating
    rateThreshold: 0.05          # rate mode: 5% error rate
    windowSeconds: 60            # rate mode: rolling window size
  drops:
    enabled: true
    mode: immediate
    minDrops: 5                  # rate mode: min drops to same dst in window
    windowSeconds: 60
  dnsFailures:
    enabled: true
    rcodes: [NXDOMAIN, SERVFAIL, REFUSED]
    mode: immediate
    minEvents: 10
    rateThreshold: 0.10
    windowSeconds: 60
  latency:
    enabled: true
    thresholdMs: 2000            # P99 threshold
    windowSize: 100              # sliding window size (samples)
```

### Underlying YAML Config

Helm renders the settings above into a ConfigMap that the container mounts at `/etc/flight-recorder/config.yaml`. You normally don't touch this file directly, but its schema is defined by `pkg/config/config.go`. For local (non-Helm) development, `testdata/config-local.yaml` shows the full format.

## Local Development with Docker

Run the full stack locally with mocked dependencies:

```bash
# Start everything (builds + starts MinIO, mock Cilium, mock Hubble, flight-recorder)
make docker-up

# Tail logs — see anomaly detection firing in real time
make docker-logs

# Quick smoke test — trigger one manual capture
make docker-test

# Full test suite — exercises all endpoints + error paths (~85 seconds, 51 assertions)
make docker-test-all

# Restart with a clean slate after code changes
make docker-restart

# Stop and clean up
make docker-down
```

### Local Services

| Service | Purpose | URL |
|---|---|---|
| `flight-recorder` | The application under test | `http://localhost:8080` |
| `mock-hubble` | Generates fake flows: drops, HTTP 5xx, DNS NXDOMAIN, latency spikes | `localhost:4245` (gRPC) |
| `mock-cilium` | Simulates Cilium agent recorder API, writes dummy PCAPs | Unix socket |
| `minio` | S3-compatible storage for captured PCAPs | Console: `http://localhost:9001` |
| `jaeger` | Receives OTLP traces and shows the capture → upload span tree | UI: `http://localhost:16686` |

MinIO credentials: `minioadmin` / `minioadmin`

### Viewing Traces

`testdata/config-local.yaml` ships with `tracing.endpoint: jaeger:4317`, so every
capture automatically emits a span tree to Jaeger. Once `make docker-up` is
running and the flight-recorder has fired at least one capture:

1. Open `http://localhost:16686`
2. Select service **flight-recorder**, then click **Find Traces**
3. Open a trace to see the span tree:
   - `capture.execute` (root span, tagged with `trigger`, `src_ip`, `dst_ip`, …)
     - `cilium.createRecorder` — PUT to the BPF recorder API
     - `cilium.stopAndCollect` — DELETE + file copy
   - `s3.Upload` (separate trace per completed capture)
     - `s3.Upload.attempt` (one child per retry attempt)

Set `tracing.endpoint: ""` in your own config to disable tracing — the code
installs a no-op tracer and spans cost effectively nothing.

### Test Suite

The test script (`scripts/test-local.sh`) validates:

| Test | What it verifies |
|---|---|
| Health check | `GET /health` returns 200 with `{status: ok}` |
| Auto-detection | All 4 trigger types fire: drops, HTTP 503, DNS NXDOMAIN, latency spikes |
| Manual capture | `POST /capture` completes end-to-end with correct metadata |
| Cooldown | Rate limiter prevents capture storms |
| S3 upload | PCAPs exist in MinIO with correct key structure |
| PCAP validity | Valid magic bytes, tcpdump-readable |
| Metadata fields | All fields present on every capture entry |
| Error handling | Invalid JSON returns 400 |

## Kubernetes Deployment (Helm)

The Flight Recorder is deployed exclusively via the Helm chart in `helm/`. No raw manifests are shipped — every knob is exposed as a Helm value.

### Quick Start

```bash
# Lint the chart (catches syntax + schema issues)
make helm-lint

# Render templates locally for review (no cluster access needed)
make helm-template

# Install or upgrade in the target cluster
make helm-install

# Diff before rolling out (requires the helm-diff plugin)
make helm-diff

# Uninstall
make helm-uninstall
```

Equivalent `helm` invocation used by the Makefile:

```bash
helm upgrade --install flight-recorder ./helm \
  -n kube-system --create-namespace \
  -f helm/values-example.yaml
```

Override variables when invoking `make`:

```bash
make helm-install \
  HELM_RELEASE=flight-recorder \
  HELM_NAMESPACE=kube-system \
  HELM_VALUES=helm/values-prod.yaml
```

### Prerequisites

The flight recorder depends on three pieces of platform plumbing; **all must be in
place before the DaemonSet will work**.

#### 1. Cilium with the BPF recorder enabled

The Cilium agent exposes a REST API for the BPF PCAP recorder on its Unix
socket. In most Cilium installs this is **off by default**; you have to opt in.

```bash
# Check whether the recorder API is reachable on a node:
kubectl -n kube-system exec ds/cilium -- \
  cilium-dbg recorder list 2>&1 | head

# If you get "recorder: feature disabled" (or similar), enable it in the
# Cilium Helm values and reinstall/upgrade Cilium:
#
#   # in your Cilium values.yaml
#   bpf:
#     enableRecorder: true
#
# Exact flag name changes between Cilium versions — consult the Cilium docs
# for your release. The flight-recorder will open its circuit breaker
# (flight_recorder_cilium_circuit_state == 1) if the API is missing.
```

#### 2. Hubble Relay reachable from the node

The watcher connects to a cluster-wide Hubble Relay Service. Verify it's up:

```bash
kubectl -n kube-system get pod -l k8s-app=hubble-relay
kubectl -n kube-system get svc hubble-relay
```

If Hubble Relay isn't installed, enable it in your Cilium Helm values
(`hubble.relay.enabled: true`) and point `hubble.address` in
`helm/values.yaml` at the resulting Service.

#### 3. S3 bucket + IRSA role (EKS)

Captured PCAPs are uploaded to S3 via the default AWS credential chain.
On EKS the cleanest path is IRSA (IAM Roles for Service Accounts). Create
the bucket, IAM policy, and role, then annotate the ServiceAccount.

**IAM policy** (`flight-recorder-s3.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WritePCAPs",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:AbortMultipartUpload"
      ],
      "Resource": "arn:aws:s3:::flight-recorder-pcaps-prod/*"
    },
    {
      "Sid": "ListForRetry",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::flight-recorder-pcaps-prod"
    }
  ]
}
```

**Trust policy** (`flight-recorder-trust.json` — replace the OIDC bits with
values from `aws eks describe-cluster --name <cluster> --query 'cluster.identity.oidc.issuer'`):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<account>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<OIDC_ID>"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "oidc.eks.<region>.amazonaws.com/id/<OIDC_ID>:sub":
          "system:serviceaccount:kube-system:flight-recorder",
        "oidc.eks.<region>.amazonaws.com/id/<OIDC_ID>:aud":
          "sts.amazonaws.com"
      }
    }
  }]
}
```

**Create the role, attach the policy, set the annotation:**

```bash
# Bucket (with a 30-day lifecycle to keep storage cheap)
aws s3api create-bucket --bucket flight-recorder-pcaps-prod --region us-east-1
aws s3api put-bucket-lifecycle-configuration \
  --bucket flight-recorder-pcaps-prod \
  --lifecycle-configuration '{"Rules":[{"ID":"expire-pcaps","Status":"Enabled","Filter":{},"Expiration":{"Days":30}}]}'

# IAM
aws iam create-policy \
  --policy-name flight-recorder-s3 \
  --policy-document file://flight-recorder-s3.json
aws iam create-role \
  --role-name flight-recorder \
  --assume-role-policy-document file://flight-recorder-trust.json
aws iam attach-role-policy \
  --role-name flight-recorder \
  --policy-arn arn:aws:iam::<account>:policy/flight-recorder-s3

# In your values-<cluster>.yaml:
#   serviceAccount:
#     annotations:
#       eks.amazonaws.com/role-arn: arn:aws:iam::<account>:role/flight-recorder
```

### Verification

After `helm upgrade --install`, run these three checks in order. Each
exercises one layer of the pipeline.

```bash
POD=$(kubectl -n kube-system get pod -l app.kubernetes.io/name=flight-recorder -o name | head -1)
kubectl -n kube-system port-forward $POD 8080:8080 &

# 1. Readiness (Hubble reachable?). Expect 200.
curl -sf http://localhost:8080/ready | jq .
# {"hubbleConnected": true, "status": "ready"}

# 2. Cilium circuit breaker (BPF recorder API reachable?). Expect 0.
curl -s http://localhost:8080/metrics | grep '^flight_recorder_cilium_circuit_state '
# flight_recorder_cilium_circuit_state 0

# 3. End-to-end (trigger → capture → S3). Expect an object in the bucket
# within ~DurationSeconds+10s.
curl -X POST http://localhost:8080/capture \
  -H 'Content-Type: application/json' \
  -d '{"srcCIDR":"10.0.0.0/8","dstCIDR":"10.0.0.0/8","dstPort":443,"durationSeconds":10}'
# {"status":"accepted","message":"capture started"}

sleep 15
aws s3 ls s3://flight-recorder-pcaps-prod/$CLUSTER/ --recursive | tail
```

If any of those fail, see [Troubleshooting](#troubleshooting) below.

### Per-Cluster Values Files

`helm/values-example.yaml` is the reference overlay. Duplicate it per cluster (e.g. `helm/values-prod.yaml`) and change only the cluster-specific bits:

```yaml
cluster:
  name: my-prod-cluster
s3:
  bucket: flight-recorder-pcaps-prod
image:
  tag: v0.1.0
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<account>:role/<role>
```

### Tuning Detection Per Environment

For production, `rate` mode with stricter thresholds avoids noise from transient errors:

```yaml
# helm/values-prod.yaml
triggers:
  httpErrors:
    mode: rate
    minEvents: 50          # only evaluate after 50 HTTP responses
    rateThreshold: 0.02    # 2% error rate sustained over the window
    windowSeconds: 120
  drops:
    mode: rate
    minDrops: 20           # require 20 drops to the same dst in the window
    windowSeconds: 60
  dnsFailures:
    mode: rate
    minEvents: 30
    rateThreshold: 0.05
    windowSeconds: 300
```

In dev, `immediate` mode is better — it surfaces every error so you can confirm the pipeline works.

### Rollout

```bash
kubectl -n kube-system rollout status ds/flight-recorder
kubectl -n kube-system logs -l app.kubernetes.io/name=flight-recorder -f
```

For the post-install health check, see [Verification](#verification) above.

### Troubleshooting

| Symptom | Likely cause | What to check |
|---|---|---|
| `/ready` returns 503 with `hubbleConnected: false` | Hubble Relay unreachable | `hubble.address` in values, DNS from pod, `kubectl -n kube-system get svc hubble-relay` |
| `flight_recorder_cilium_circuit_state == 1` | Cilium socket unreachable or BPF recorder disabled | `kubectl exec ds/cilium -- cilium-dbg recorder list`; enable `bpf.enableRecorder=true` in Cilium |
| `flight_recorder_cilium_circuit_trips_total` climbs steadily | Cilium agent crash-looping or overloaded | `kubectl -n kube-system logs ds/cilium --previous` |
| `flight_recorder_flows_processed_total == 0` | Hubble connected but no flows arriving | Hubble RBAC (the `hubble-relay-client-certs` secret); `cilium hubble observe` on a node |
| PCAPs in `/tmp/flight-recorder/` but not in S3 | IRSA role missing / bucket policy denies PutObject | `kubectl describe sa flight-recorder` for the role annotation; check `flight_recorder_upload_attempts_total{outcome="terminal"}` |
| `flight_recorder_flows_dropped_total` > 0 | Detector CPU-bound; flow channel full | Bump `resources.requests.cpu`, simplify triggers (drop `rate` mode if you don't need it) |
| `ImagePullBackOff` on every pod | `image.repository` points at a registry you haven't pushed to | Either build and push `flight-recorder:{{ appVersion }}`, or point at the public image (see [Container Image](#container-image)) |
| `flight_recorder_keys_evicted_total{reason="capacity"}` > 0 persistently | Busy cluster; `detector.maxTrackedKeys` too low for your tuple cardinality | Raise `detector.maxTrackedKeys` (memory scales linearly) |
| Captures fire but PCAPs are always empty (24 bytes) | BPF recorder filter didn't match any packets | Broaden the filter; confirm Cilium datapath sees the flow (`hubble observe --from-ip … --to-ip …`) |
| Pod memory creeping up | Per-tuple maps unbounded | Ensure `detector.idleEvictAfterSeconds` is set and the janitor is ticking (`rate(flight_recorder_keys_evicted_total[5m])` should be > 0 on a busy cluster) |

### Sizing

Memory and CPU scale with **flow volume** and **tuple cardinality** (unique
`src IP → dst IP:port` pairs). Ballpark on an EKS node streaming 5k flows/s
with ~500 active tuples:

- **Memory**: ~80–120 MiB steady state (Go runtime ~40 MiB, per-tuple rate
  windows ~10–20 MiB, capture buffers negligible). The 512 MiB default limit
  in `values.yaml` gives ~4× headroom for burst tuple expansion.
- **CPU**: 20–40 m with four triggers in `immediate` mode. `rate` mode is
  cheaper (no per-flow work when under threshold).

Scaling knobs when a node is underspec'd:

| Problem | Knob |
|---|---|
| CPU-bound detector | Raise `resources.requests.cpu`; move hot triggers to `rate` mode |
| Memory pressure | Lower `detector.maxTrackedKeys`; shorten `detector.idleEvictAfterSeconds`; shorten trigger `windowSeconds` |
| Flow drops under spikes | Accept them — the channel buffer (256) is sized to absorb 2–3 seconds of backlog; rate > that means the detector can't keep up and more memory won't help |

### Monitoring & Alerts

The chart ships an opt-in `PrometheusRule` with alerts for the Cilium
circuit opening, Hubble disconnection, sustained S3 failures, flow drops,
and total capture failure. Enable with:

```yaml
prometheusRule:
  enabled: true
  labels:
    release: kube-prometheus-stack   # if your Prometheus Operator's ruleSelector uses this
```

Requires the Prometheus Operator CRDs (`monitoring.coreos.com/v1`) in the
target cluster.

### NetworkPolicy

`/metrics` and `/capture` both listen on port 8080, which means any pod in
the cluster can trigger a capture by default. In a cluster with a NetworkPolicy
controller, turn on the bundled policy to restrict ingress:

```yaml
networkPolicy:
  enabled: true
  scrapeFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
  apiFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
  # Your cluster pod + service CIDRs (adjust for your CNI)
  clusterCIDRs:
    - 10.100.0.0/16
    - 172.20.0.0/16
```

### Terraform (EKS)

The supporting AWS infrastructure (S3 bucket + IRSA role) is not included in this
repo. You'll need, at minimum:

- An S3 bucket (e.g. `flight-recorder-pcaps`) with a lifecycle rule that expires
  captured PCAPs after a retention window that matches your compliance needs.
- An IAM role with `s3:PutObject` on that bucket, bound to the pod's
  ServiceAccount via IRSA (EKS OIDC trust).

### Container Image

Tagged releases publish a multi-arch image (linux/amd64 + linux/arm64) to
GitHub Container Registry via the `.github/workflows/release.yml`
workflow. Each release pushes three tags for the same digest:

| Tag | Example | Use case |
|---|---|---|
| `v<semver>` | `v0.1.0` | Cloud-native convention, matches the Git tag |
| `<semver>` | `0.1.0` | Exact match for the Helm chart version |
| `latest` | `latest` | Tracks the most recent release (avoid in production) |

To use the published image:

```yaml
image:
  repository: ghcr.io/vperez237/flight-recorder
  tag: v0.1.0
```

If you fork the repo, your own release tags will push to
`ghcr.io/<your-gh-user>/flight-recorder`.

To build and push manually (bypassing CI):

```bash
docker build --target flight-recorder \
  -t <your-registry>/flight-recorder:v0.1.0 .
docker push <your-registry>/flight-recorder:v0.1.0
```

Then point `image.repository` / `image.tag` at that image in your values file
and re-run `make helm-upgrade`.

### Helm Chart Distribution

The release workflow also packages and pushes the chart to an OCI registry
on tagged commits, so you can install without cloning:

```bash
helm install flight-recorder \
  oci://ghcr.io/vperez237/charts/flight-recorder \
  --version 0.1.0 \
  -n kube-system --create-namespace \
  -f my-values.yaml
```

To publish manually:

```bash
helm registry login ghcr.io -u <your-user>
make helm-package
make helm-publish CHART=flight-recorder-0.1.0.tgz
```

### Versioning

The project follows semantic versioning (`MAJOR.MINOR.PATCH`). The Helm
chart's `version` and `appVersion` track the same number for simplicity —
both are rewritten by the release workflow from the Git tag.

| Change | Version bump |
|---|---|
| API-breaking change to `/capture` request/response shape | MAJOR |
| Rename or removal of a Helm value | MAJOR |
| Rename of a Prometheus metric | MAJOR |
| New trigger, new config field (with default), new metric | MINOR |
| Bug fix that doesn't alter external behavior | PATCH |

Internal Go package layout (`pkg/detector`, `pkg/capture`, etc.) is not
treated as a stable API — the module isn't intended to be imported by
external projects.

## API

| Endpoint | Method | Description |
|---|---|---|
| `/capture` | POST | Trigger a manual PCAP capture |
| `/captures` | GET | List recent captures (paginated, newest first) |
| `/health` | GET | Liveness probe — 200 while the process is alive |
| `/ready` | GET | Readiness probe — 200 only while Hubble is connected, 503 otherwise |
| `/metrics` | GET | Prometheus metrics |

### POST /capture

```bash
curl -X POST http://localhost:8080/capture \
  -H "Content-Type: application/json" \
  -d '{
    "srcCIDR": "10.0.1.0/24",
    "dstCIDR": "10.0.2.0/24",
    "dstPort": 8080,
    "protocol": "TCP",
    "durationSeconds": 30
  }'
```

Body fields:

| Field | Type | Notes |
|---|---|---|
| `srcCIDR` | string | Source IP or CIDR. Empty means "any". |
| `dstCIDR` | string | Destination IP or CIDR. Empty means "any". |
| `dstPort` | number | 0–65535. 0 means "any". |
| `protocol` | string | `TCP`, `UDP`, `ICMPv4`, `ICMPv6`. Defaults to `TCP`. |
| `durationSeconds` | number | 0 means "use the server default". |

Responses:

- `202 Accepted` — capture started, body is `{"status":"accepted","message":"capture started"}`
- `400 Bad Request` — invalid JSON, bad IP/CIDR, out-of-range port, unsupported protocol, or negative duration. Body is `{"error":"…"}`.

### GET /captures

```bash
# Default: up to 100 newest entries
curl -s http://localhost:8080/captures | jq .

# Pagination: 5 per page, skip the 10 most recent
curl -s 'http://localhost:8080/captures?limit=5&offset=10' | jq .

# Filter by trigger
curl -s 'http://localhost:8080/captures?trigger=drop' | jq .
```

Query parameters:

| Parameter | Default | Notes |
|---|---|---|
| `limit` | `100` | Max items to return. Capped at 1000. |
| `offset` | `0` | Skip the N most recent entries. |
| `trigger` | *(none)* | One of `drop`, `http_error`, `dns_failure`, `latency`, `manual`. |

Response headers include `X-Total-Count`: the total after filtering, before pagination.

Response:

```json
[
  {
    "trigger": "drop",
    "reason": "packet dropped: POLICY_DENIED",
    "srcIP": "10.0.1.139",
    "dstIP": "10.0.2.203",
    "dstPort": 8080,
    "filePath": "/tmp/flight-recorder/20260326T140747Z_drop_10.0.1.139_10.0.2.203_8080.pcap",
    "startTime": "2026-03-26T14:07:47.984595636Z",
    "duration": "10.002643113s"
  }
]
```

### S3 Key Structure

```
s3://{bucket}/{cluster}/{node}/{YYYY}/{MM}/{DD}/{timestamp}_{trigger}_{src}_{dst}_{port}.pcap
```

Example: `flight-recorder-pcaps/example-cluster/ip-10-0-1-42/2026/03/26/20260326T140747Z_drop_10.0.1.139_10.0.2.203_8080.pcap`

The date is split into `YYYY/MM/DD` path segments so prefix-based S3 lifecycle
rules and operator browsing (`aws s3 ls bucket/cluster/node/2026/`) work without
parsing filenames.

Each object includes S3 metadata: trigger, reason, source/dest IPs, port, protocol, duration, node, cluster, timestamp.

## Viewing PCAPs

Download captures from MinIO (local) or S3 (production) and inspect them with standard tools:

```bash
# Download from local MinIO
mc alias set local http://localhost:9000 minioadmin minioadmin
mc ls local/flight-recorder-pcaps --recursive
mc cp local/flight-recorder-pcaps/<key> ./capture.pcap

# Quick summary
tcpdump -r capture.pcap -nn

# Open in Wireshark (GUI)
wireshark capture.pcap

# Filter with tshark (CLI)
tshark -r capture.pcap -Y "http"
tshark -r capture.pcap -q -z conv,tcp
```
