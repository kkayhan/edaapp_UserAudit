# EDA User Audit

A Nokia **EDA** app that turns the EDA cluster into a system-of-record for **who did what**. Once installed, it silently and continuously records:

- every **configuration change** made in EDA — the user who made it, when, from which IP address, and a human-readable diff of what changed on each device
- every **sign-in and sign-out** to the EDA GUI
- every **administrative change** in Keycloak (user / group / role management)

All events are written to daily log files (`EDA-user-events-YYYY-MM-DD.log`) on a **persistent volume inside the cluster**, so they survive controller restarts, upgrades, and node reboots. Logs are exposed read-only over a simple HTTP endpoint — no scraping, no parsing, no extra tooling.

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
  name: kkayhan-catalog
  namespace: eda-system
spec:
  enabled: true
  remoteType: git
  remoteURL: https://github.com/kkayhan/eda-catalog.git
  refreshInterval: 180
  title: kkayhan community catalog
```

> This is the shared **kkayhan community catalog** — the same one entry also brings the
> other community apps (Grafana, Image Manager). If you've already added it for another
> app, skip this step.

**Step 2 — Install from the Store:**

Open the **App Store** in the EDA UI. "EDA User Audit" will appear under *Monitoring*. Click **Install**. That's it — no settings to fill in, no credentials to configure.

The controller starts immediately, enables Keycloak event auditing on your behalf, and begins writing the first log file within one poll cycle (default: 5 minutes).

---

## Where the logs are

### Persistent storage

Logs live on a `PersistentVolumeClaim` inside the cluster (`useraudit-data`, 500 MiB by default). Restarting the pod, upgrading the app, or rolling a node does **not** lose data. Uninstalling the app **does** — pull a copy first if you need to keep history.

### HTTP endpoint

Logs are served read-only over the EDA HttpProxy at `https://<your-eda-host>/core/httpproxy/v1/useraudit/logs/`.

**Who can read them.** EDA authenticates and authorizes every request before it reaches the app, and only members of the **`system-administrator`** user group are allowed through. See [Access control](#access-control) for how that works and how to widen it.

**Step 0 — get an access token.** Every call needs an EDA bearer token. This is the standard [EDA API authentication flow](https://docs.eda.dev/development/api/#getting-the-access-token): ask an EDA administrator for the Keycloak client secret of the `eda` client, then exchange your own EDA username and password for a token.

```bash
EDA=https://<your-eda-host>
TOKEN=$(curl -sk "$EDA/core/httpproxy/v1/keycloak/realms/eda/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=password' \
  --data-urlencode 'client_id=eda' \
  --data-urlencode 'scope=openid' \
  --data-urlencode "client_secret=$EDA_CLIENT_SECRET" \
  --data-urlencode "username=$EDA_USERNAME" \
  --data-urlencode "password=$EDA_PASSWORD" | jq -r .access_token)
```

Tokens are short-lived (~5 minutes by default), so acquire one per run rather than storing it. On some deployments Keycloak is routed at `/core/proxy/v1/identity` instead of `/core/httpproxy/v1/keycloak` — if the first path 404s, try the other. The helper script below handles all of this for you.

**Step 1 — list the available log files.** A `GET` on `/logs/` returns a JSON array of every file currently on disk, with sizes and timestamps:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" https://<your-eda-host>/core/httpproxy/v1/useraudit/logs/
```

```json
[
  {"name": "EDA-user-events-2026-05-03.log", "size_bytes": 18432, "modified": "2026-05-03T23:59:00Z"},
  {"name": "EDA-user-events-2026-05-04.log", "size_bytes":  4221, "modified": "2026-05-04T08:14:12Z"}
]
```

**Step 2 — download a specific file.** Append the `name` from the listing to the URL:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://<your-eda-host>/core/httpproxy/v1/useraudit/logs/EDA-user-events-2026-05-04.log
```

### Access control

The app's HttpProxy uses `authType: inApiServer`, which makes the **EDA API server** the enforcement point. Two checks run there, before a request ever reaches the app:

1. **Authentication.** A valid Keycloak bearer token must be present. Without one the request is rejected with `HTTP 400 InvalidAuthHeader` — there is no anonymous access and no separate app password to manage.
2. **Authorization.** EDA applies its own RBAC to the URL. Reaching `/core/httpproxy/v1/useraudit/**` requires a **URL rule** covering that path, and the only role shipped with a matching rule is the default `system-administrator` `ClusterRole` (`urlRules: [{path: /**, permissions: readWrite}]`). Roles are assigned through user groups, so in practice access means **membership of the `system-administrator` group**. Anyone else is authenticated but rejected with `HTTP 403`.

**Give collectors their own account — not admin.** Membership of `system-administrator` cannot be attenuated: the group exists to carry a role granting `resourceRules: * readWrite` and `urlRules: /** readWrite`, so a "read-only" member is a contradiction — they get full write access to EDA. A cron job that pulls log files should not hold that. Create a dedicated role, group, and user instead (roles attach to **groups**, never directly to users, so all three are needed):

```bash
# role -> group -> user, via EDA's admin API as an administrator
curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "$EDA/core/admin/roles" -d '{"name":"readonly","namespace":"eda-system",
    "description":"Read-only access to all of EDA. No write anywhere.",
    "resourceRules":[{"apiGroups":["*"],"resources":["*"],"permissions":"read"}],
    "tableRules":[{"path":".**","permissions":"read"}],
    "urlRules":[{"path":"/**","permissions":"read"}]}'

curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "$EDA/core/admin/groups" -d '{"name":"readonly","description":"Read-only across EDA."}'
GUUID=$(curl -sk -H "Authorization: Bearer $TOKEN" "$EDA/core/admin/groups" | jq -r '.[]|select(.name=="readonly").uuid')
curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "$EDA/core/admin/groups/$GUUID/roles" -d '["readonly"]'

curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "$EDA/core/admin/users" -d '{"username":"useraudit-readonly","email":"useraudit-readonly@eda.local",
    "firstName":"UserAudit","lastName":"Reader","enabled":true}'
UUUID=$(curl -sk -H "Authorization: Bearer $TOKEN" "$EDA/core/admin/users" | jq -r '.[]|select(.username=="useraudit-readonly").uuid')
curl -sk -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "$EDA/core/admin/users/$UUUID/groups" -d "[\"$GUUID\"]"
curl -sk -X PUT  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "$EDA/core/admin/users/$UUUID/resetpassword" -d '{"value":"<password>","temporary":false}'
```

The same is available in the UI under **System Administration → User Management**. Each of these returns `400` if you try to shortcut it: a group cannot be created with `roles`, a user cannot be created with `groups` or `password`, `email`/`firstName`/`lastName` are mandatory, and Keycloak rejects punctuation (e.g. parentheses) in first/last names.

The collector then needs no Keycloak admin credentials — only the account and the `eda` client secret:

```bash
EDA_USERNAME=useraudit-readonly EDA_PASSWORD=... EDA_CLIENT_SECRET=... \
  ./pull-audit-logs.sh https://<your-eda-host> /var/audit-archive
```

Want the account restricted to *only* the audit log rather than read-only across EDA? Drop `resourceRules` and `tableRules` from the role above and narrow the URL rule to `/core/httpproxy/v1/useraudit/**`.

EDA rules are additive with implicit deny, so the same mechanism widens access for any other group — no change to the app is needed:

```yaml
apiVersion: core.eda.nokia.com/v1
kind: ClusterRole
metadata:
  name: audit-log-reader
  namespace: eda-system
spec:
  description: Read-only access to the EDA User Audit log endpoint.
  urlRules:
    - path: /core/httpproxy/v1/useraudit/**
      permissions: read
```

Two consequences worth knowing:

- **The token is stripped before forwarding.** The app never sees who called it, so it cannot record log-download activity in its own audit trail. Read access is visible in EDA/Keycloak, not in the log files.
- **Browsers cannot open the URL directly.** EDA accepts the token only in an `Authorization` header — not a cookie, not a query parameter — so pasting the URL into a browser returns `HTTP 400` rather than a login page. Access is via `curl`, the helper script, or any SIEM/collector that can set a header.

### Need SFTP? Relay it from outside the cluster

The app deliberately exposes **HTTP(S) only**. Versions v26.4.1-6 … v26.4.1-9 also shipped an in-pod SFTP sidecar; it was **removed in v26.4.1-10** in favour of relaying from a host outside the cluster, because that:

- keeps the app to a single container and a single protocol — no SSH daemon, no host keys, no extra Service on the EDA VIP, and no default credentials shipped with the app;
- puts the audit copy **off-cluster**, so it survives loss of the cluster — which is exactly what an audit trail needs;
- lets the SFTP account, password policy, and retention be owned by whoever owns the relay host, not baked into an app manifest.

The pattern is a small cron job on any Linux host that can reach EDA over HTTPS: pull with the two calls above into a directory, then serve that directory over the host's own SFTP. Since the listing reports `size_bytes`, a puller only needs to re-fetch files whose size changed — the current day's file grows, finished days are frozen. Write to a temp file and `mv` into place so a collector never reads a half-written file. [`logs/pull-audit-logs.sh`](logs/pull-audit-logs.sh) is a working starting point.

### Helper script

[`logs/pull-audit-logs.sh`](logs/pull-audit-logs.sh) wraps all three steps — token acquisition included — so you can grab everything in one command. Pure `bash` + `curl`, no other dependencies:

```bash
# Download every log file into the current directory
EDA_USERNAME=admin EDA_PASSWORD=... ./pull-audit-logs.sh https://<your-eda-host>

# Download every log file into ./audit-archive
EDA_USERNAME=admin EDA_PASSWORD=... ./pull-audit-logs.sh https://<your-eda-host> ./audit-archive

# Download a single named file
EDA_USERNAME=admin EDA_PASSWORD=... ./pull-audit-logs.sh https://<your-eda-host> ./audit-archive EDA-user-events-2026-05-04.log
```

Credentials come from the environment: `EDA_USERNAME` / `EDA_PASSWORD` (the EDA user to log in as — must be in the `system-administrator` group), and optionally `EDA_CLIENT_SECRET`. If you don't supply the client secret the script fetches it for you using `KC_USERNAME` / `KC_PASSWORD` (the Keycloak master-realm admin). Already hold a token? Set `EDA_TOKEN` and no other credential is read. The script locates Keycloak itself and re-acquires the token mid-run if it expires.

### Health check

```bash
curl -sk -H "Authorization: Bearer $TOKEN" https://<your-eda-host>/core/httpproxy/v1/useraudit/healthz
```

Returns a JSON object with overall status, last poll time, last transaction ID processed, and per-subsystem health for the EDA API and Keycloak event feeds.

---

## Seeing the real user IP in the logs

By default the `IPADDR` field in your audit log shows a cluster-internal address (typically `10.244.0.1`) instead of the real laptop / browser IP. **This is not an app bug.** Two normal Kubernetes behaviors erase the source IP before Keycloak sees the request:

1. **kube-proxy SNAT.** The `eda-api` Service defaults to `externalTrafficPolicy: Cluster`, which rewrites the source IP to an internal gateway (`10.244.0.1`) so reply packets find their way back — before `eda-api` ever sees your real IP.
2. **Pod-to-pod forwarding.** `eda-api` then forwards the request internally to Keycloak. It does carry a client IP across that hop in a forward header (that's what `ProxyMode` controls) — but by then the value is already the SNAT-rewritten `10.244.0.1`, so that is what Keycloak logs.

For the real IP to survive, two things must hold: **(a)** whatever terminates your external connection must observe your real IP (not a kube-proxy-rewritten one), and **(b)** that IP must reach Keycloak in an HTTP forward header. EDA's `eda-api` already handles **(b)** — its `ProxyMode` setting controls how it writes and trusts `Forwarded` / `X-Forwarded-For` headers (see Nokia's [Platform security → Proxy forward headers](https://docs.eda.dev/user-guide/security/platform-security/#proxy-forward-headers)). The missing piece is **(a)**: by default the `eda-api` Service uses `externalTrafficPolicy: Cluster`, whose SNAT rewrites your source IP to `10.244.0.1` before `eda-api` ever sees it.

How you restore **(a)** depends on your cluster:

- **Single-node or directly-exposed clusters** — the external VIP points straight at `eda-api`, with no reverse proxy in front. One Service setting turns off the SNAT; **no ingress required.** Start here — it's a one-liner and it keeps the audit IP tamper-proof. See [Single-node / directly-exposed clusters](#single-node--directly-exposed-clusters-no-ingress).
- **Multi-node clusters, or any cluster already behind a reverse proxy** — put an Ingress controller in front of `eda-api` to read the real IP off the socket and inject `X-Forwarded-For`. Nokia ships a kpt package for [Ingress NGINX](https://kubernetes.github.io/ingress-nginx/). See [Kind-based](#kind-based-clusters) / [Talos-based](#talos-based-clusters).

Nokia leaves the ingress piece to the cluster admin — [Exposing the UI/API](https://docs.eda.dev/software-install/exposing-ui-api/):

> "Ingress controllers are not part of Nokia EDA installation, and are typically managed by the cluster administrator."

---

### Single-node / directly-exposed clusters (no ingress)

If your EDA VIP routes straight to the `eda-api` Service — the common single-node case, with no ingress-nginx and no reverse proxy in front — you don't need any of the ingress machinery below. The only thing corrupting the source IP is the kube-proxy SNAT, and one Service setting disables it.

#### Step 1 — Stop the SNAT on `eda-api`

`externalTrafficPolicy: Local` tells kube-proxy not to rewrite the source IP of traffic arriving at the `eda-api` Service. Since `eda-api` is what terminates your connection, it now sees your real client IP directly.

```bash
kubectl -n eda-system patch svc eda-api -p '{"spec":{"externalTrafficPolicy":"Local"}}'
```

**Safe on a single node.** `Local` only risks dropping traffic on a *multi-node* cluster — on nodes that don't happen to run the `eda-api` pod. On a single node there is nowhere else for traffic to go, so reachability is unchanged; only the SNAT stops. Rollback is the same command with `Cluster`.

#### Step 2 — Leave `ProxyMode` at `None` (the default)

You do **not** need to touch `ProxyMode`, and on a directly-exposed cluster you shouldn't. With `ProxyMode: None`, `eda-api` **drops any client-supplied `Forwarded` / `X-Forwarded-*` headers and generates a fresh one from the real TCP peer** — so the logged IP is authoritative and a client cannot spoof it by sending its own header. Confirm it's `None`:

```bash
kubectl -n eda-system get engineconfig engine-config -o jsonpath='{.spec.cluster.external.proxyMode}{"\n"}'
# Expect: None
```

> ⚠️ **Do not set `ProxyMode: XForward` on a directly-exposed cluster.** `XForward` makes `eda-api` *trust* a client-supplied `X-Forwarded-For`, which is correct only when a sanitizing reverse proxy sits in front to overwrite it. Without that proxy, any client can forge the logged IP by sending its own `X-Forwarded-For` header. `XForward` belongs with the ingress recipe below — not this one.

#### Verify

Close **all** EDA browser tabs (or restart the browser), then sign in fresh and pull the log:

```bash
./pull-audit-logs.sh https://<your-eda-host> . && tail -5 *-$(date +%Y-%m).log
```

The `IPADDR` on the new `EDA-Login` event should be your real browser IP — not `10.244.0.x`.

> **Why close the tabs first?** `externalTrafficPolicy` changes how *new* connections are handled; connections opened *before* the change keep their old NAT until they close. The EDA UI holds long-lived keep-alive connections, so a tab left open from before the patch keeps logging `10.244.0.1` until it reconnects.

**Two caveats:**

- **Re-apply after an EDA core upgrade.** An upgrade can re-render the `eda-api` Service and reset `externalTrafficPolicy` to `Cluster`. The symptom announces itself — `10.244.0.1` reappears in the log — and the fix is re-running the Step 1 patch.
- **Internal service logins still show cluster IPs.** `CLIENT_LOGIN` events from EDA's own components (`eda-api-server`, `eda-useraudit`) legitimately originate inside the cluster, so they keep internal addresses. Only interactive user logins carry a real client IP.

---

**Ingress approach (multi-node, or already behind a reverse proxy).** Use this when `eda-api` is *not* the edge — a real load balancer or reverse proxy terminates client TLS, or you run more than one node so `externalTrafficPolicy: Local` isn't safe. You install an Ingress controller that reads the real client IP off the socket and injects `X-Forwarded-For`, then switch `ProxyMode` to `XForward` so `eda-api` trusts it. The procedure differs slightly between Kind and Talos installs; pick your section below.

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

**Where:** the package ships under `eda-kpt/eda-external-packages/eda-api-ingress-https/` in your EDA playground checkout (commonly `/home/kkayhan/eda/playground/...`).

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

**Where:** the package ships under `eda-kpt/eda-external-packages/eda-api-ingress-https/` in your EDA playground checkout (commonly `/home/kkayhan/eda/playground/...`).

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
- Does **not** require (or accept) any credentials of its own — it reads existing Kubernetes secrets inside the cluster, and log access is authenticated by EDA rather than by an app-local password.
- Does **not** implement per-file or per-user filtering of its own. Access is all-or-nothing and enforced by EDA RBAC: a caller who is allowed to reach the endpoint can read every log file. Restricting *which* logs a reader sees is not supported.
- Does **not** log who downloaded a log file. EDA strips the caller's token before forwarding, so the app cannot see the reader's identity; read access is visible in EDA and Keycloak instead.
