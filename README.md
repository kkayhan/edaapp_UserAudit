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
2026-04-20T09:12:33 UTC | Event=Transaction-104 | User=alice | IPADDR=10.0.0.5 | Modified=Fabric | Namespace=default | Fabric resource named fabric1 has been updated.
   interface-ethernet/ethernet-1-1/admin-state: enable -> disable
2026-04-20T11:05:14 UTC | Event=KC-Admin | User=admin | IPADDR=10.0.0.5 | Action=CREATE | Target=user | Detail=created user "bob".
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

You may notice the `IPADDR` field in your audit log shows a cluster-internal address (typically `10.244.0.1`) instead of the real laptop / browser IP of the user. **This is not an app bug** — it's a property of how Kubernetes routes external traffic. Fixing it is a cluster-admin task. This chapter explains why and what to do.

### Why the IP gets lost

When a user signs in from a browser, the packet travels:

```
laptop  →  cluster VIP  →  kube-proxy  →  eda-api pod  →  Keycloak pod
```

The "source IP" on the packet gets rewritten twice along the way:

1. **kube-proxy SNAT.** Kubernetes Services default to `externalTrafficPolicy: Cluster`, which rewrites the source IP to an internal gateway address (`10.244.0.1`) so reply packets find their way back.
2. **Pod-to-pod forwarding.** Even if Step 1 preserved the IP, `eda-api` re-issues the request to Keycloak internally — the source address becomes `eda-api`'s own pod IP.

By the time Keycloak logs the event, the real client IP is gone from the TCP packet. The only place to recover it is the HTTP `X-Forwarded-For` header — but something at the cluster edge has to *add* that header in the first place. Vanilla EDA doesn't ship anything that does.

The Nokia EDA docs ([Exposing the UI/API](https://docs.eda.dev/software-install/exposing-ui-api/)) state plainly:

> "Ingress controllers are not part of Nokia EDA installation, and are typically managed by the cluster administrator."

So for any cluster where audit logs need to show real user IPs, the cluster admin must install an Ingress controller. Nokia documents two options — [Ingress NGINX](https://kubernetes.github.io/ingress-nginx/) and the [Gateway API](https://gateway-api.sigs.k8s.io/) — but only Ingress NGINX has a ready-to-apply Nokia kpt package (`eda-api-ingress-https`). The rest of this chapter assumes Ingress NGINX.

### What needs to be true

For a real user IP to land in the audit log, all four of these have to be in place:

| # | Piece | What it does |
|---|---|---|
| 1 | **ingress-nginx** Helm chart with `externalTrafficPolicy: Local` | HTTP-aware proxy at the cluster edge. Reads the real client IP off the TCP socket and stamps it into `X-Forwarded-For`. `Local` keeps kube-proxy from rewriting the IP on the way in. |
| 2 | Nokia **`eda-api-ingress-https`** kpt package applied | Provides the `Ingress` resource + TLS Cert that route UI traffic through ingress-nginx. Ships under `eda-kpt/eda-external-packages/`. |
| 3 | **`EngineConfig.spec.cluster.external.proxyMode: XForward`** | Tells EDA to start Keycloak with `--proxy-headers=xforwarded`, so Keycloak trusts the header instead of the TCP source IP. |
| 4 | MetalLB pool with **`autoAssign: false`** | Stops `eda-api` from claiming the cluster's single VIP, so ingress-nginx can claim it instead via `controller.service.loadBalancerIP=<VIP>`. |

All four are cluster-admin tasks. Skipping any one of them breaks the chain.

### ingress-nginx Helm install — four mandatory values

```bash
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --set controller.service.externalTrafficPolicy=Local \
  --set controller.service.loadBalancerIP=<your-VIP> \
  --set controller.config.annotations-risk-level=Critical \
  --set controller.allowSnippetAnnotations=true
```

The last two are **not optional**. The Nokia Ingress uses a `server-snippet` annotation to enlarge Keycloak's HTTP header buffer (OAuth tokens are big). Modern ingress-nginx (≥ v1.10) classifies that annotation as Critical risk and **silently drops the entire Ingress** unless you whitelist it. Symptom if you forget: `nginx.conf` has zero references to `eda-api` and every request returns the default-backend 404.

Also, before `kubectl apply`-ing the kpt package, strip the empty IPv6 placeholder from the Cert YAML — cert-manager rejects empty strings in `spec.ipAddresses`:

```bash
yq eval '(.spec.ipAddresses // []) |= map(select(. != ""))' -i eda-api-ingress-cert.yaml
```

### Kind-based clusters

- Kind runs as Docker containers on the host. The five-piece chain above applies as-is.
- `EngineConfig.proxyMode` is **not** set to `XForward` by default on a Kind install. Either add it to your kpt-setters before installing EDA, or set it on the live `EngineConfig` afterwards.
- No hypervisor in the path → no extra host-level NAT to worry about.

### Talos-based clusters

- The default Nokia kpt-setters for Talos already include `EXT_PROXY_MODE=XForward`, so piece **3** is done out of the box. You still need pieces **1, 2, and 4**.
- **Do not** set `EngineConfig.spec.api.serviceType: ClusterIP` as a shortcut on EDA 26.4.1. The api-server reconciler unconditionally writes `allocateLoadBalancerNodePorts: false` onto the Service, which Kubernetes rejects on non-`LoadBalancer` types, looping the reconciler forever and blocking the install. The MetalLB `autoAssign: false` approach is correct — `eda-api` stays `type: LoadBalancer`, goes `EXTERNAL-IP=<pending>`, and is still reachable via its ClusterIP for ingress-nginx backend traffic.

### Verifying it worked

After all four cluster-admin pieces are in place, sign in fresh from a browser and pull the latest log file using the helper script:

```bash
./pull-audit-logs.sh https://<your-eda-host> . && tail -5 *-$(date +%Y-%m).log
```

The `IPADDR` field on the new login event should show your real browser IP — not `10.244.0.x`.

---

## What it does NOT do

- Does **not** forward logs to external systems (syslog / SIEM / S3). Pull logs over HTTP into whatever system you already run.
- Does **not** require (or accept) any credentials — it reads existing Kubernetes secrets inside the cluster.
- Does **not** filter log access per user. Anyone authenticated to EDA can read the audit log.
