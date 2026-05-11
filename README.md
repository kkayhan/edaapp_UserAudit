# EDA User Audit

An EDA App that automatically logs every EDA configuration change and Keycloak authentication event into monthly audit log files. Logs are served over a read-only HTTP API and are visible in the EDA UI.

- **Repo:** https://github.com/kkayhan/edaapp_UserAudit
- **Packages:** published to GHCR under the same account
- **App ID:** `useraudit.eda.edacommunity.com`
- **Category:** Monitoring
- **Vendor:** EDACommunity

## What It Logs

- **EDA transactions** — every configuration change, with user, source IP, timestamp, and a flattened per-device diff.
- **Keycloak GUI sign-in / sign-out** — user login and logout events with username and source IP.
- **Keycloak admin events** — user, group, client-role, and realm modifications performed through Keycloak.

### Sample Log Output

```
2026-04-16T12:20:22 UTC | Event=Transaction-99 | User=admin | IPADDR=10.0.0.5 | Modified=Fabric | Namespace=default | Fabric resource named fabric1 has been updated.
   interface-ethernet/ethernet-1-1/admin-state: enable -> disable

2026-04-16T12:22:40 UTC | Event=EDA-Login | User=admin | IPADDR=10.244.0.27 | The user signed-in to the EDA GUI.
```

## Prerequisites

- EDA v25.12.x or later
- The EDA cluster can reach `ghcr.io`

## Installation

### Step 1 — Add the catalog

Apply a Catalog CR that points EDA at this repo:

```yaml
apiVersion: appstore.eda.nokia.com/v1
kind: Catalog
metadata:
  name: community-apps
  namespace: eda-system
spec:
  remoteURL: https://github.com/kkayhan/edaapp_UserAudit.git
  skipTLSVerify: false
  title: Community EDA Apps
```

```bash
kubectl apply -f catalog.yaml
```

### Step 2 — Install from the App Store

Open the EDA GUI, go to the **App Store**, find **EDA User Audit** under *Monitoring*, and click **Install**.

Or install via CLI:

```yaml
apiVersion: appstore.eda.nokia.com/v1
kind: AppInstaller
metadata:
  name: install-useraudit
  namespace: eda-system
spec:
  operation: install
  dryRun: false
  apps:
    - appId: useraudit.eda.edacommunity.com
      catalog: community-apps
      version:
        type: semver
        value: "v0.7.0"
```

```bash
kubectl apply -f install.yaml
```

### Step 3 — Post-install setup

Create the default configuration:

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: useraudit.eda.edacommunity.com/v1alpha1
kind: UserAuditConfig
metadata:
  name: default
spec:
  pollIntervalSeconds: 300
  retentionMonths: 0
EOF
```

### Step 4 — Verify

```bash
kubectl -n eda-system get pods -l eda.nokia.com/app=eda-useraudit
curl -sk https://<eda-address>/core/httpproxy/v1/useraudit/healthz
```

## Usage

All endpoints are reached via the EDA HttpProxy:

```
https://<eda-address>/core/httpproxy/v1/useraudit/
```

| Endpoint | Description |
|----------|-------------|
| `/healthz` | Health status and last poll time |
| `/logs/` | List log files with sizes and timestamps (JSON) |
| `/logs/<filename>` | Download a specific log file (plain text) |

```bash
EDA=https://<eda-address>
BASE=$EDA/core/httpproxy/v1/useraudit

curl -sk $BASE/healthz
curl -sk $BASE/logs/
curl -sk $BASE/logs/EDA-user-events-2026-05.log
```

## Configuration

### UserAuditConfig CRD

```bash
kubectl edit userauditconfig default
```

| Field | Default | Range | Description |
|-------|---------|-------|-------------|
| `pollIntervalSeconds` | 300 | 60–3600 | Polling interval in seconds |
| `retentionMonths` | 0 | 0+ | Months of logs to keep (0 = unlimited) |

### App settings (install-time)

Adjustable from the EDA App Store settings panel:

| Setting | Default | Description |
|---------|---------|-------------|
| `controllerCpuLimit` | 200m | CPU limit |
| `controllerMemoryLimit` | 128Mi | Memory limit |
| `logStorageSize` | 500Mi | PVC size for log storage |

## Uninstalling

```yaml
apiVersion: appstore.eda.nokia.com/v1
kind: AppInstaller
metadata:
  name: uninstall-useraudit
  namespace: eda-system
spec:
  operation: delete
  dryRun: false
  apps:
    - appId: useraudit.eda.edacommunity.com
      catalog: community-apps
```

Or remove it via the App Store UI.

## Build from source

Requires `edabuilder` (ships in the EDA toolbox pod).

```bash
# Authenticate once
edabuilder login registry ghcr.io -u <gh-user> -p <gh-pat>          # PAT: write:packages

# Build and push OCI packages to GHCR
edabuilder build-push --app manifest=useraudit/manifest.yaml

# Publish the catalog entry to this repo
edabuilder login git -u <gh-user> -p <gh-pat> \
  https://github.com/kkayhan/edaapp_UserAudit.git
edabuilder publish https://github.com/kkayhan/edaapp_UserAudit.git \
  --app manifest=useraudit/manifest.yaml
```

For dev iteration against a local EDA cluster, `edabuilder deploy --app useraudit` pushes to the in-cluster registry and creates an AppInstaller.

## Troubleshooting

- **Pod in `ImagePullBackOff`** — verify the cluster can reach `ghcr.io`. Images are public; no auth needed.
- **Health reports `degraded` / `error`** — `kubectl get userauditconfig default -o yaml` plus pod logs.
- **No logs appear** — the controller auto-discovers the latest transaction ID on first start and logs new events going forward. Make a change in EDA and wait for the next poll cycle.
- **HttpProxy 404** — verify the HttpProxy CR: `kubectl get httpproxies.core.eda.nokia.com useraudit`.
