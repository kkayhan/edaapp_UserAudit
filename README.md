# EDA User Audit

A Nokia **EDA** app that turns the EDA cluster into a system-of-record for **who did what**. Once installed, it silently and continuously records:

- every **configuration change** made in EDA — the user who made it, when, from which IP address, and a human-readable diff of what changed on each device
- every **sign-in and sign-out** to the EDA GUI
- every **administrative change** in Keycloak (user / group / role management)

All events are written to monthly log files (`Transaction-YYYY-MM.log`) on a **persistent volume inside the cluster**, so they survive controller restarts, upgrades, and node reboots. Logs are exposed read-only over a simple HTTP endpoint — no scraping, no parsing, no extra tooling.

A typical line looks like this:

```
2026-04-20T08:41:00 UTC | Event=EDA-Login | User=admin | IPADDR=10.244.0.55 | The user signed-in to the EDA GUI.
2026-04-20T07:26:09 UTC | Event=Transaction-101 | User=kubernetes | Modified=EDA | Namespace=eda | TargetNode resource named leaf2 has been created.
2026-05-12T19:49:21 UTC | Event=Transaction-230 | User=admin | IPADDR=10.244.0.1 | Modified=d-bl1 | Namespace=demo | (+)interface/ethernet-1/1/description client555
2026-05-12T19:49:21 UTC | Event=Transaction-230 | User=admin | IPADDR=10.244.0.1 | Modified=d-bl1 | Namespace=demo | (-)interface/ethernet-1/1/description client123
```

Designed for compliance archives, SIEM feeds, change-management audits, and "who broke the fabric last Tuesday?" conversations.

---

## Install (from the EDA UI)

There's nothing to configure. The app starts logging the moment it's installed.

**Step 1 — Add this catalog to your EDA cluster (one-time):**

1. In the EDA UI, go to **System Administration**.
2. Under **APP Management**, open **Catalogs**.
3. Click **Create** and paste the YAML below.
4. **Commit**.

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

**Step 2 — Install from the Store:**

Open the **App Store** in the EDA UI. "EDA User Audit" will appear under *Monitoring*. Click **Install**. That's it — no settings to fill in, no credentials to configure.

The controller starts immediately, enables Keycloak event auditing on your behalf, and begins writing the first log file within one poll cycle (default: 5 minutes).

---

## Where the logs are

### Persistent storage

Logs live on a `PersistentVolumeClaim` inside the cluster (`useraudit-data`, 500 MiB by default). Restarting the pod, upgrading the app, or rolling a node does **not** lose data. Uninstalling the app **does** — pull a copy first if you need to keep history.

### HTTP endpoint

Logs are served read-only over the EDA HttpProxy at `https://<your-eda-host>/core/httpproxy/v1/useraudit/logs/`.

**Step 1 — list the available log files.** A `GET` on `/logs/` returns a JSON array of every file currently on disk, with sizes and timestamps:

```bash
curl -sk https://<your-eda-host>/core/httpproxy/v1/useraudit/logs/
```

```json
[
  {"name": "Transaction-2026-04.log", "size_bytes": 18432, "modified": "2026-04-30T23:59:00Z"},
  {"name": "Transaction-2026-05.log", "size_bytes":  4221, "modified": "2026-05-04T08:14:12Z"}
]
```

**Step 2 — download a specific file.** Append the `name` from the listing to the URL:

```bash
curl -sk https://<your-eda-host>/core/httpproxy/v1/useraudit/logs/Transaction-2026-05.log
```

### Helper script

[`logs/pull-audit-logs.sh`](logs/pull-audit-logs.sh) wraps both steps so you can grab everything in one command. Pure `bash` + `curl`, no other dependencies:

```bash
# Download every log file into the current directory
./pull-audit-logs.sh https://<your-eda-host>

# Download every log file into ./audit-archive
./pull-audit-logs.sh https://<your-eda-host> ./audit-archive

# Download a single named file
./pull-audit-logs.sh https://<your-eda-host> ./audit-archive Transaction-2026-05.log
```

### Health check

```bash
curl -sk https://<your-eda-host>/core/httpproxy/v1/useraudit/healthz
```

Returns a JSON object with overall status, last poll time, last transaction ID processed, and per-subsystem health for the EDA API and Keycloak event feeds.

---

## Seeing the real user IP in the logs

By default the `IPADDR` field in your audit log shows a cluster-internal address (typically `10.244.0.1`) instead of the real laptop / browser IP. **This is not an app bug.** Two normal Kubernetes behaviors erase the source IP before Keycloak sees the request:

1. **kube-proxy SNAT.** Services default to `externalTrafficPolicy: Cluster`, which rewrites the source IP to an internal gateway (`10.244.0.1`) so reply packets find their way back.
2. **Pod-to-pod forwarding.** `eda-api` re-issues the request internally to Keycloak — the source becomes `eda-api`'s own pod IP.

The real client IP can only survive end-to-end as an HTTP `X-Forwarded-For` header — but **vanilla EDA doesn't ship anything that injects that header.** Nokia is explicit about this in [Exposing the UI/API](https://docs.eda.dev/software-install/exposing-ui-api/):

> "Ingress controllers are not part of Nokia EDA installation, and are typically managed by the cluster administrator."

The fix is for you, the cluster admin, to install an Ingress controller in front of `eda-api`. Nokia ships a kpt package for [Ingress NGINX](https://kubernetes.github.io/ingress-nginx/) — that's what these steps use. The procedure differs slightly between Kind and Talos installs; pick your section.

---

### Kind-based clusters

Four steps, ~10 minutes end-to-end on a working Kind cluster.

#### Step 1 — Install ingress-nginx

**What:** an HTTP-aware proxy at the cluster edge that reads the real client IP off the TCP socket and stamps it into `X-Forwarded-For`.

**Where:** on the Kind cluster, via Helm. Run from any host with `helm` + `kubectl` pointing at the cluster.

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --set controller.service.externalTrafficPolicy=Local \
  --set controller.service.loadBalancerIP=<your-VIP> \
  --set controller.config.annotations-risk-level=Critical \
  --set controller.allowSnippetAnnotations=true
```

`<your-VIP>` is the external IP your EDA UI resolves to. All four `--set` values are mandatory:

| Value | Why |
|---|---|
| `externalTrafficPolicy=Local` | Tells kube-proxy NOT to SNAT incoming traffic — otherwise the real client IP gets rewritten before ingress-nginx ever sees it. |
| `loadBalancerIP=<your-VIP>` | Tells MetalLB to assign your specific VIP to ingress-nginx (claimed back from `eda-api` in Step 2). |
| `annotations-risk-level=Critical` + `allowSnippetAnnotations=true` | Nokia's Ingress uses a `server-snippet` annotation to enlarge Keycloak's HTTP header buffer (OAuth tokens are big). Modern ingress-nginx (≥ v1.10) classifies this annotation as "Critical risk" and **silently drops the entire Ingress** unless you whitelist it. Symptom if you forget: `nginx.conf` has zero references to `eda-api`, every request returns the default-backend 404. |

Verify the controller comes up:

```bash
kubectl -n ingress-nginx get pods
kubectl -n ingress-nginx get svc ingress-nginx-controller
```

The Service shows `EXTERNAL-IP=<pending>` for now — Step 2 frees the VIP for it.

#### Step 2 — Free the VIP from `eda-api`

**What:** by default `eda-api` claims the cluster's single VIP via MetalLB. ingress-nginx needs that VIP. Setting the MetalLB pool to `autoAssign: false` means MetalLB only allocates the VIP to Services that explicitly request it via `loadBalancerIP` — ingress-nginx does (Step 1), `eda-api` doesn't.

**Where:** patch the MetalLB IPAddressPool that owns your VIP (commonly named `kind` from `playground/configs/metallb-config-defaultPool.yaml`):

```bash
kubectl -n metallb-system patch ipaddresspool kind --type merge \
  -p '{"spec":{"autoAssign":false}}'
```

If `eda-api` already holds the VIP (existing install), force MetalLB to re-evaluate by deleting and re-applying the Service so it loses its `loadBalancer.ingress` allocation:

```bash
kubectl -n eda-system get svc eda-api -o yaml > /tmp/eda-api.yaml
kubectl -n eda-system delete svc eda-api
kubectl apply -f /tmp/eda-api.yaml
```

Verify the new state:

```bash
kubectl -n eda-system get svc eda-api                      # EXTERNAL-IP=<pending>
kubectl -n ingress-nginx get svc ingress-nginx-controller  # EXTERNAL-IP=<your-VIP>
```

`eda-api` in `<pending>` is the correct final state — it's still reachable on its ClusterIP, which is all ingress-nginx needs for backend traffic.

#### Step 3 — Apply Nokia's `eda-api-ingress-https` kpt package

**What:** the `Ingress` resource and TLS Cert that route UI traffic from ingress-nginx into `eda-api`. The Ingress also carries the `server-snippet` annotation that Step 1 whitelisted.

**Where:** the package ships under `eda-kpt/eda-external-packages/eda-api-ingress-https/` in your EDA playground checkout (commonly `/root/eda/playground/...`).

Strip the empty IPv6 placeholder from the Cert YAML first — cert-manager rejects `""` entries in `spec.ipAddresses`:

```bash
cd <eda-playground>/eda-kpt/eda-external-packages/eda-api-ingress-https
yq eval '(.spec.ipAddresses // []) |= map(select(. != ""))' -i eda-api-ingress-cert.yaml
kubectl apply -f .
```

Wait for the cert to issue (usually ~30s):

```bash
kubectl -n eda-system get certificate eda-api-ingress-cert -w
# Expect READY=True
```

#### Step 4 — Enable `XForward` mode on `EngineConfig`

**What:** tells EDA's reconciler to start Keycloak with `--proxy-headers=xforwarded`, so Keycloak trusts the `X-Forwarded-For` header from ingress-nginx instead of using the TCP source IP.

**Where:** on Kind this is **not** set by default. Patch the live `EngineConfig`:

```bash
kubectl -n eda-system patch engineconfig engine-config --type merge \
  -p '{"spec":{"cluster":{"external":{"proxyMode":"XForward"}}}}'
```

EDA's reconciler picks this up and rolls Keycloak with the new flag within ~30s. Confirm:

```bash
kubectl -n eda-system get pods | grep -i keycloak
kubectl -n eda-system describe pod <keycloak-pod> | grep -i 'proxy-headers'
# Expect: --proxy-headers=xforwarded
```

For a fresh install, set `EXT_PROXY_MODE=XForward` in `playground/configs/kpt-setters.yaml` before running `make eda-install-apps` — the kpt render bakes it in.

#### Verify on Kind

Sign in fresh from a browser, then pull the latest audit log:

```bash
./pull-audit-logs.sh https://<your-eda-host> . && tail -5 *-$(date +%Y-%m).log
```

The `IPADDR` field on the new `EDA-Login` event should be your real browser IP — not `10.244.0.x`.

---

### Talos-based clusters

Four steps, ~10 minutes end-to-end on a working Talos cluster. Step 4 is effectively a no-op on a default Talos install — Nokia's kpt-setters already enable `XForward` mode out of the box — but you should still verify it's set. Watch for one EDA-26.4.1 trap in Step 2.

#### Step 1 — Install ingress-nginx

**What:** an HTTP-aware proxy at the cluster edge that reads the real client IP off the TCP socket and stamps it into `X-Forwarded-For`.

**Where:** on the Talos cluster, via Helm. Run from any host with `helm` + `kubectl` pointing at the cluster.

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --set controller.service.externalTrafficPolicy=Local \
  --set controller.service.loadBalancerIP=<your-VIP> \
  --set controller.config.annotations-risk-level=Critical \
  --set controller.allowSnippetAnnotations=true
```

`<your-VIP>` is the external IP your EDA UI resolves to. All four `--set` values are mandatory:

| Value | Why |
|---|---|
| `externalTrafficPolicy=Local` | Tells kube-proxy NOT to SNAT incoming traffic — otherwise the real client IP gets rewritten before ingress-nginx ever sees it. |
| `loadBalancerIP=<your-VIP>` | Tells MetalLB to assign your specific VIP to ingress-nginx (claimed back from `eda-api` in Step 2). |
| `annotations-risk-level=Critical` + `allowSnippetAnnotations=true` | Nokia's Ingress uses a `server-snippet` annotation to enlarge Keycloak's HTTP header buffer (OAuth tokens are big). Modern ingress-nginx (≥ v1.10) classifies this annotation as "Critical risk" and **silently drops the entire Ingress** unless you whitelist it. Symptom if you forget: `nginx.conf` has zero references to `eda-api`, every request returns the default-backend 404. |

Verify the controller comes up:

```bash
kubectl -n ingress-nginx get pods
kubectl -n ingress-nginx get svc ingress-nginx-controller
```

The Service shows `EXTERNAL-IP=<pending>` for now — Step 2 frees the VIP for it.

#### Step 2 — Free the VIP from `eda-api`

**What:** by default `eda-api` claims the cluster's single VIP via MetalLB. ingress-nginx needs that VIP. Setting the MetalLB pool to `autoAssign: false` means MetalLB only allocates the VIP to Services that explicitly request it via `loadBalancerIP` — ingress-nginx does (Step 1), `eda-api` doesn't.

**Where:** patch the MetalLB IPAddressPool that owns your VIP:

```bash
kubectl -n metallb-system patch ipaddresspool <pool-name> --type merge \
  -p '{"spec":{"autoAssign":false}}'
```

If `eda-api` already holds the VIP (existing install), force MetalLB to re-evaluate by deleting and re-applying the Service so it loses its `loadBalancer.ingress` allocation:

```bash
kubectl -n eda-system get svc eda-api -o yaml > /tmp/eda-api.yaml
kubectl -n eda-system delete svc eda-api
kubectl apply -f /tmp/eda-api.yaml
```

**Trap to avoid:** don't take the shortcut of setting `EngineConfig.spec.api.serviceType: ClusterIP`. On EDA 26.4.1 the api-server reconciler unconditionally writes `allocateLoadBalancerNodePorts: false` onto the Service. Kubernetes rejects that field on non-`LoadBalancer` types ("Forbidden: may only be used when type is 'LoadBalancer'"), the reconciler loops forever, and core install gets stuck. Stick with MetalLB `autoAssign: false` — `eda-api` stays `type: LoadBalancer` (in `<pending>` state) and ingress-nginx claims the VIP cleanly.

Verify the new state:

```bash
kubectl -n eda-system get svc eda-api                      # EXTERNAL-IP=<pending>
kubectl -n ingress-nginx get svc ingress-nginx-controller  # EXTERNAL-IP=<your-VIP>
```

`eda-api` in `<pending>` is the correct final state — it's still reachable on its ClusterIP, which is all ingress-nginx needs for backend traffic.

#### Step 3 — Apply Nokia's `eda-api-ingress-https` kpt package

**What:** the `Ingress` resource and TLS Cert that route UI traffic from ingress-nginx into `eda-api`. The Ingress also carries the `server-snippet` annotation that Step 1 whitelisted.

**Where:** the package ships under `eda-kpt/eda-external-packages/eda-api-ingress-https/` in your EDA playground checkout (commonly `/root/eda/playground/...`).

Strip the empty IPv6 placeholder from the Cert YAML first — cert-manager rejects `""` entries in `spec.ipAddresses`:

```bash
cd <eda-playground>/eda-kpt/eda-external-packages/eda-api-ingress-https
yq eval '(.spec.ipAddresses // []) |= map(select(. != ""))' -i eda-api-ingress-cert.yaml
kubectl apply -f .
```

Wait for the cert to issue (usually ~30s):

```bash
kubectl -n eda-system get certificate eda-api-ingress-cert -w
# Expect READY=True
```

#### Step 4 — Confirm `XForward` is set on `EngineConfig`

**What:** EDA needs to start Keycloak with `--proxy-headers=xforwarded` so it trusts the `X-Forwarded-For` header from ingress-nginx instead of using the TCP source IP. On Talos installs this is already configured by Nokia's default kpt-setters (`EXT_PROXY_MODE=XForward`) — you only need to verify it.

**Where:** check the live `EngineConfig` in `eda-system`:

```bash
kubectl -n eda-system get engineconfig engine-config -o yaml \
  | grep -A2 'external:'
# Expect to see:    proxyMode: XForward
```

If for some reason `proxyMode` is missing (custom kpt-setters, hand-edited install), patch it on:

```bash
kubectl -n eda-system patch engineconfig engine-config --type merge \
  -p '{"spec":{"cluster":{"external":{"proxyMode":"XForward"}}}}'
```

EDA's reconciler picks this up and rolls Keycloak with the new flag within ~30s. Confirm the flag landed on the running pod:

```bash
kubectl -n eda-system get pods | grep -i keycloak
kubectl -n eda-system describe pod <keycloak-pod> | grep -i 'proxy-headers'
# Expect: --proxy-headers=xforwarded
```

#### Verify on Talos

Sign in fresh from a browser, then pull the latest audit log:

```bash
./pull-audit-logs.sh https://<your-eda-host> . && tail -5 *-$(date +%Y-%m).log
```

`IPADDR` on the new `EDA-Login` event should be your real browser IP — not `10.244.0.x`.

---

## What it does NOT do

- Does **not** forward logs to external systems (syslog / SIEM / S3). Pull logs over HTTP into whatever system you already run.
- Does **not** require (or accept) any credentials — it reads existing Kubernetes secrets inside the cluster.
- Does **not** filter log access per user. Anyone authenticated to EDA can read the audit log.
