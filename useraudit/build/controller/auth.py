"""
Token management and TLS context for the EDA User Audit controller.

The app runs on ONE dedicated service-account identity (`eda-useraudit`, `eda` realm). A single
client_credentials token drives BOTH the EDA API (via the `edarole_system-administrator` realm
role) AND the Keycloak admin API for event auditing (via realm-management roles manage-realm/
view-events/view-users). No human user, no `admin/admin`, no assumed password.

Runtime credential model (v26.4.1-4):
  - RUNTIME: authenticate with the PERSISTED client secret (k8s secret `eda-useraudit-client`).
    This needs NO KC master admin. Once provisioned, the app keeps working even if the KC
    master-admin password later changes / the `keycloak-admin-secret` goes stale.
  - PROVISIONING ONLY (first install, or client deleted/rotated): `keycloak-admin-secret` (KC
    master admin) is used ONCE to create the client, grant the roles, fetch + persist the secret.
    KC master admin is never used in the steady state.

History: v26.4.1-2 read `eda-realm-auth-secret` (admin/admin bootstrap seed) via password grant —
broke when the EDA admin password changed. v26.4.1-3 replaced it with a self-provisioned service
account but re-provisioned (needing KC master admin) on every start. v26.4.1-4 persists the client
secret so the steady state needs no admin credential at all. v26.4.1-5 hardens that steady state:
the stored-secret path now runs KC-base discovery too (v26.4.1-4 inherited the unprobed default,
which 404s forever on deployments routing KC at /core/proxy/v1/identity), a failed probe round is
never pinned (re-probes next call instead of wedging on a transient eda-api outage), and any 403
triggers a one-shot re-provision so stripped roles are re-granted (self-heal parity with -3).

Builds an SSLContext from the EDA internal trust bundle + eda-api-ca secret.
"""

import json
import logging
import os
import ssl
import time
import urllib.error
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen

import k8s

logger = logging.getLogger("auth")

_NAMESPACE = os.environ.get("POD_NAMESPACE", "eda-system")
_TRUST_BUNDLE = "/var/run/eda/tls/internal/trust/trust-bundle.pem"
_TIMEOUT = 30

# In-cluster base URLs. The EDA API base is stable; the Keycloak base differs by
# EDA release/deployment. 26.4.3 (and this 26.4.1 lab) expose Keycloak under the
# generic HttpProxy at /core/httpproxy/v1/keycloak; other 26.4.1 deployments route
# it at the native /core/proxy/v1/identity (where the `keycloak` HttpProxy CR
# forwards). Hardcoding one path 404s on clusters using the other and wedges
# first-run init, so we probe candidates once and pin the working one (_ensure_kc_base).
_EDA_API_BASE = "https://eda-api.eda-system.svc"
_KC_BASE_CANDIDATES = [
    _EDA_API_BASE + "/core/httpproxy/v1/keycloak",                      # 26.4.3 + this 26.4.1 lab (verified)
    _EDA_API_BASE + "/core/proxy/v1/identity",                         # 26.4.1 native identity route
    "https://eda-keycloak.eda-system.svc:9443/core/proxy/v1/identity",  # direct to keycloak, last resort
]
_KC_BASE = _KC_BASE_CANDIDATES[0]  # pinned by _ensure_kc_base() at first token call

# Dedicated service-account client the controller self-provisions in the `eda` realm.
# ONE client_credentials token on this client drives EVERYTHING the app does:
#   - _EDA_ROLE (realm role)                -> the EDA API (transaction/v2, ...) authorizes on it
#   - _REALM_MGMT_ROLES (realm-management)  -> the Keycloak admin API (events/users/enable-events)
# No human user, no password. The client secret is PERSISTED (v26.4.1-4) in k8s secret
# _STORED_SECRET_NAME so that at runtime the app authenticates with ONLY that stored secret and
# needs NO keycloak-admin-secret (KC master admin) — that is used only for one-time provisioning.
_SVC_CLIENT_ID = "eda-useraudit"
# The EDA realm role the service account holds. This is the Keycloak role that EDA
# auto-creates from the `useraudit-controller` EDA ClusterRole shipped in
# manifests/edarole.yaml: read-only on resources, and URL access limited to
# /core/transaction/**.
#
# Up to v26.4.1-12 this was `edarole_system-administrator` -- readWrite on everything,
# for an app that only reads. _ensure_service_client now also REVOKES that legacy role,
# because granting the new one without removing the old would leave the account an
# administrator and make the change cosmetic.
_EDA_ROLE = "edarole_useraudit-controller"
_LEGACY_EDA_ROLES = ["edarole_system-administrator"]
# realm-management client roles the SA needs for the KC admin API. view-users is a composite that
# also grants query-users/query-groups (covers /users + /groups); manage-realm covers enable-events
# (PUT /admin/realms/eda); view-events covers /events + /admin-events. Verified sufficient on 26.4.1.
_REALM_MGMT_ROLES = ["manage-realm", "view-events", "view-users"]
_STORED_SECRET_NAME = "eda-useraudit-client"   # k8s Secret holding the SA client secret
_STORED_SECRET_KEY = "clientSecret"
# Marks which role profile the stored credential was provisioned under. The runtime
# fast path deliberately skips provisioning, so without this an upgrade would keep
# using the existing token and NEVER pick up a change to _EDA_ROLE -- the account
# would stay an administrator forever. A mismatch forces exactly one re-provision.
_STORED_PROFILE_KEY = "roleProfile"
_ROLE_PROFILE = "v2-least-privilege"

# Token cache: (token_string, expiry_epoch)
_kc_admin_token_cache = [None, 0]
_eda_api_token_cache = [None, 0]
_svc_client_secret_cache = [None]   # in-mem cache of the dedicated service-account client secret
_kc_base_cache = [None]   # set once _ensure_kc_base() pins the working Keycloak base

# SSL context singleton
_ssl_context = [None]


def _build_ssl_context():
    """Build SSLContext from trust bundle + eda-api-ca secret."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    loaded = False
    # Load internal trust bundle
    try:
        if os.path.exists(_TRUST_BUNDLE):
            ctx.load_verify_locations(_TRUST_BUNDLE)
            loaded = True
    except Exception as e:
        logger.warning("Failed to load trust bundle: %s", e)
    # Load eda-api-ca from secret
    try:
        secret = k8s.read_secret("eda-api-ca", _NAMESPACE)
        ca_crt = secret.get("ca.crt", "")
        if ca_crt:
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
                f.write(ca_crt)
                f.flush()
                ctx.load_verify_locations(f.name)
                loaded = True
            os.unlink(f.name)
    except Exception as e:
        logger.warning("Failed to load eda-api-ca: %s", e)
    if not loaded:
        logger.warning("No CA certificates loaded; falling back to unverified TLS")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_ssl_context():
    if _ssl_context[0] is None:
        _ssl_context[0] = _build_ssl_context()
    return _ssl_context[0]


_PROBE_TIMEOUT = 8   # probes run serially over up to 3 candidates; keep an outage cheap


def _ensure_kc_base():
    """Probe the candidate Keycloak bases (unauthenticated .well-known GET on the master
    realm) and pin _KC_BASE to the first that answers 2xx. EDA releases and deployments
    route Keycloak under different relative paths; a hardcoded base 404s on the others.

    Pin ONLY on a successful probe. If every probe fails (e.g. eda-api briefly down while
    this pod starts), keep the default for this attempt but do NOT cache it — the next
    call re-probes. Pinning an unverified default here would permanently wedge the app on
    clusters whose real base is a later candidate (the failure only surfaces as 404s on
    every token/admin call, long after the outage has passed)."""
    global _KC_BASE
    if _kc_base_cache[0]:
        return
    ctx = get_ssl_context()
    for base in _KC_BASE_CANDIDATES:
        url = f"{base}/realms/master/.well-known/openid-configuration"
        try:
            with urlopen(Request(url=url, method="GET"), context=ctx, timeout=_PROBE_TIMEOUT) as resp:
                if 200 <= resp.status < 300:
                    _KC_BASE = base
                    _kc_base_cache[0] = base
                    logger.info("Keycloak base discovered: %s", base)
                    return
                logger.info("Keycloak base probe %s -> HTTP %s", url, resp.status)
        except urllib.error.HTTPError as e:
            logger.info("Keycloak base probe %s -> HTTP %s", url, e.code)
        except Exception as e:
            logger.info("Keycloak base probe %s -> %s", url, e)
    logger.warning("No Keycloak base probe succeeded; using default %s for this attempt "
                   "(unpinned — will re-probe on the next call)", _KC_BASE)


def _http_post_form(url, fields, ssl_ctx):
    data = urlencode(fields).encode("utf-8")
    req = Request(url=url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urlopen(req, context=ssl_ctx, timeout=_TIMEOUT) as resp:
            raw = resp.read()
            return json.loads(raw.decode("utf-8")) if raw else None
    except urllib.error.HTTPError as e:
        logger.warning("POST %s -> HTTP %s", url, e.code)
        raise


def http_json(method, url, headers, data, ssl_ctx):
    """Generic HTTP JSON request used by other modules."""
    req = Request(url=url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urlopen(req, context=ssl_ctx, timeout=_TIMEOUT) as resp:
            raw = resp.read()
            return json.loads(raw.decode("utf-8")) if raw else None
    except urllib.error.HTTPError as e:
        # 404 is expected/handled by callers (e.g. the per-id transaction look-ahead
        # scan probes ids that don't exist yet) -> debug, not warning. Surface 5xx.
        if e.code >= 500:
            logger.warning("%s %s -> HTTP %s", method, url, e.code)
        else:
            logger.debug("%s %s -> HTTP %s", method, url, e.code)
        raise


def _kc_token_url(realm):
    return f"{_KC_BASE}/realms/{realm}/protocol/openid-connect/token"


def get_kc_admin_token(force=False):
    """Acquire KC admin token from keycloak-admin-secret (master realm, admin-cli)."""
    now = time.time()
    if not force and _kc_admin_token_cache[0] and now < _kc_admin_token_cache[1] - 30:
        return _kc_admin_token_cache[0]

    _ensure_kc_base()  # pin the working Keycloak base before building any token URL

    secret = k8s.read_secret("keycloak-admin-secret", _NAMESPACE)
    username = secret.get("username")
    password = secret.get("password")
    if not username or not password:
        raise RuntimeError("keycloak-admin-secret missing username or password")

    resp = _http_post_form(_kc_token_url("master"), {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": username,
        "password": password,
    }, get_ssl_context())

    if not resp or "access_token" not in resp:
        raise RuntimeError("KC admin auth failed: no access_token")

    token = resp["access_token"]
    expires_in = resp.get("expires_in", 300)
    _kc_admin_token_cache[0] = token
    _kc_admin_token_cache[1] = now + expires_in
    logger.info("KC admin token acquired (expires in %ds)", expires_in)
    return token


def _kc_admin_json(method, path, admin_token, body=None):
    """method+path against the KC admin API with an optional JSON body.
    Returns parsed JSON (or None for empty 2xx bodies). Raises HTTPError on non-2xx."""
    url = _KC_BASE + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    return http_json(method, url, headers, data, get_ssl_context())


def _get_stored_client_secret():
    """Return (secret, role_profile) from the persisted k8s Secret; (None, None) if absent.
    This is the runtime-preferred path — it needs NO KC master admin.

    role_profile records which _EDA_ROLE the credential was provisioned under, so an
    upgrade that changes the role can force a single re-provision instead of silently
    continuing with the old (over-privileged) grant."""
    try:
        data = k8s.read_secret(_STORED_SECRET_NAME, _NAMESPACE)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None
        raise
    data = data or {}
    return (data.get(_STORED_SECRET_KEY) or None), (data.get(_STORED_PROFILE_KEY) or None)


def _store_client_secret(secret):
    """Persist the service-account client secret so future runs authenticate without KC admin."""
    try:
        k8s.create_or_update_secret(_STORED_SECRET_NAME, _NAMESPACE,
                                    {_STORED_SECRET_KEY: secret,
                                     _STORED_PROFILE_KEY: _ROLE_PROFILE})
        logger.info("Persisted service-account client secret to k8s secret %s (role profile %s)",
                    _STORED_SECRET_NAME, _ROLE_PROFILE)
    except Exception as e:
        # Non-fatal: the app still works this run (in-mem secret); it just re-provisions next start.
        logger.warning("Could not persist client secret to %s: %s", _STORED_SECRET_NAME, e)


def _ensure_realm_mgmt_roles(sa_id, admin_token):
    """Grant the SA the realm-management client roles it needs to drive the KC admin API
    (events/users/enable-events) — so the SAME service-account token serves both the EDA API
    and Keycloak admin, and the app never needs KC master admin at runtime. Idempotent."""
    rm = _kc_admin_json("GET", "/admin/realms/eda/clients?clientId=realm-management",
                        admin_token) or []
    rm_id = next((c.get("id") for c in rm if c.get("clientId") == "realm-management"), None)
    if not rm_id:
        raise RuntimeError("realm-management client not found in realm 'eda'")
    have = {r.get("name") for r in (_kc_admin_json(
        "GET", f"/admin/realms/eda/users/{sa_id}/role-mappings/clients/{rm_id}", admin_token) or [])}
    missing = [r for r in _REALM_MGMT_ROLES if r not in have]
    if not missing:
        return
    to_grant = []
    for name in missing:
        role = _kc_admin_json("GET", f"/admin/realms/eda/clients/{rm_id}/roles/{quote(name)}",
                              admin_token)
        if not role or "id" not in role:
            raise RuntimeError(f"realm-management role {name} not found")
        to_grant.append({"id": role["id"], "name": role["name"]})
    _kc_admin_json("POST", f"/admin/realms/eda/users/{sa_id}/role-mappings/clients/{rm_id}",
                   admin_token, to_grant)
    logger.info("Granted realm-management roles %s to service account of %s", missing, _SVC_CLIENT_ID)


def _get_or_create_realm_role(name, admin_token):
    """Return the Keycloak realm role `name`, creating it if it does not exist.

    EDA creates `edarole_<x>` in Keycloak LAZILY — only when an administrator assigns
    the EDA ClusterRole `<x>` to a user *group* through the EDA API. Shipping the
    ClusterRole as a cr: component therefore does NOT produce a realm role. The
    controller assigns its role directly to its own service account and no human ever
    puts it on a group, so on a fresh install the role would simply not exist and every
    provisioning attempt would fail.

    Creating it here closes that gap. EDA authorizes on the NAME, so a realm role
    created directly in Keycloak binds to the ClusterRole of the same name — verified
    end to end on 26.4.1: with the role created this way and granted directly to a
    principal, all of summary / inputresources / execution / diffs/nodecfg returned 200
    with full content, while writes returned 403."""
    try:
        role = _kc_admin_json("GET", f"/admin/realms/eda/roles/{quote(name)}", admin_token)
        if role and "id" in role:
            return role
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
    logger.info("Realm role %s absent — creating it (EDA only creates these lazily on "
                "group assignment, and this one is bound directly to a service account)", name)
    try:
        _kc_admin_json("POST", "/admin/realms/eda/roles", admin_token, {
            "name": name,
            "description": ("Least-privilege role for the EDA User Audit controller. Bound to "
                            "the useraudit-controller EDA ClusterRole shipped with the app."),
        })
    except urllib.error.HTTPError as e:
        if e.code != 409:   # 409 = another replica/restart won the race; re-GET below
            raise
    role = _kc_admin_json("GET", f"/admin/realms/eda/roles/{quote(name)}", admin_token)
    if not role or "id" not in role:
        raise RuntimeError(f"Could not create or read realm role {name} in realm 'eda'")
    return role


def _revoke_legacy_roles(sa_id, admin_token, current_roles):
    """Remove superseded, over-privileged realm roles from the service account.

    Granting a narrower role without removing the old one leaves the account exactly as
    privileged as before, so the tightening would be cosmetic. Best-effort: a failure to
    revoke must not break auditing (the app still has the role it needs), it just leaves
    the account broader than intended, which is logged loudly."""
    stale = [r for r in current_roles if r.get("name") in _LEGACY_EDA_ROLES]
    if not stale:
        return
    body = [{"id": r["id"], "name": r["name"]} for r in stale if r.get("id")]
    try:
        _kc_admin_json("DELETE", f"/admin/realms/eda/users/{sa_id}/role-mappings/realm",
                       admin_token, body)
        logger.info("Revoked legacy role(s) %s from service account of %s",
                    [r["name"] for r in body], _SVC_CLIENT_ID)
    except Exception as e:
        logger.warning("Could not revoke legacy role(s) %s from %s (still holding them): %s",
                       [r.get("name") for r in body], _SVC_CLIENT_ID, e)


def _ensure_service_client(admin_token):
    """Idempotently ensure the dedicated `eda-useraudit` confidential service-account client
    exists in the `eda` realm, holds _EDA_ROLE (EDA API) + _REALM_MGMT_ROLES (KC admin API), and
    return its client secret — also persisting it (_store_client_secret) for the runtime path.
    Needs KC master admin, so this is called ONLY on first provisioning / self-heal, never in the
    steady state (see get_eda_api_token, which prefers the stored secret)."""
    if _svc_client_secret_cache[0]:
        return _svc_client_secret_cache[0]

    # 1. Find the client, creating it if absent.
    clients = _kc_admin_json("GET", f"/admin/realms/eda/clients?clientId={_SVC_CLIENT_ID}",
                             admin_token) or []
    kc_id = next((c.get("id") for c in clients if c.get("clientId") == _SVC_CLIENT_ID), None)
    if not kc_id:
        body = {
            "clientId": _SVC_CLIENT_ID,
            "name": "EDA User Audit (service account)",
            "description": ("Dedicated service-account client for the EDA User Audit app. "
                            "Auth via client_credentials; no human password. Self-managed by "
                            "the eda-useraudit controller — safe to delete to revoke access."),
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
        }
        try:
            _kc_admin_json("POST", "/admin/realms/eda/clients", admin_token, body)
        except urllib.error.HTTPError as e:
            if e.code != 409:  # 409 = a concurrent create won the race; fall through to re-GET
                raise
        clients = _kc_admin_json("GET", f"/admin/realms/eda/clients?clientId={_SVC_CLIENT_ID}",
                                 admin_token) or []
        kc_id = next((c.get("id") for c in clients if c.get("clientId") == _SVC_CLIENT_ID), None)
        if not kc_id:
            raise RuntimeError(f"Failed to create/find service client {_SVC_CLIENT_ID}")
        logger.info("Provisioned dedicated service client %s", _SVC_CLIENT_ID)

    # 2. Ensure the service account holds the EDA realm role that the API authorizes on.
    sa = _kc_admin_json("GET", f"/admin/realms/eda/clients/{kc_id}/service-account-user",
                        admin_token) or {}
    sa_id = sa.get("id")
    if not sa_id:
        raise RuntimeError(f"Service client {_SVC_CLIENT_ID} has no service-account user")
    have = _kc_admin_json("GET", f"/admin/realms/eda/users/{sa_id}/role-mappings/realm",
                          admin_token) or []
    if not any(r.get("name") == _EDA_ROLE for r in have):
        role = _get_or_create_realm_role(_EDA_ROLE, admin_token)
        _kc_admin_json("POST", f"/admin/realms/eda/users/{sa_id}/role-mappings/realm",
                       admin_token, [{"id": role["id"], "name": role["name"]}])
        logger.info("Granted %s to service account of %s", _EDA_ROLE, _SVC_CLIENT_ID)

    # Drop any legacy over-privileged role. Ordered deliberately AFTER the grant above:
    # if acquiring the new role failed we have already raised, so we can never strip the
    # account's only means of access and leave it unable to read anything.
    _revoke_legacy_roles(sa_id, admin_token, have)

    # 2b. Ensure the realm-management roles for the KC admin API (events/users/enable-events).
    _ensure_realm_mgmt_roles(sa_id, admin_token)

    # 3. Fetch the (Keycloak-generated) client secret, cache + persist it.
    sec = _kc_admin_json("GET", f"/admin/realms/eda/clients/{kc_id}/client-secret",
                         admin_token) or {}
    val = sec.get("value") or sec.get("secret")
    if not val:
        raise RuntimeError(f"Failed to fetch client secret for {_SVC_CLIENT_ID}")
    _svc_client_secret_cache[0] = val
    _store_client_secret(val)
    return val


def _client_credentials(secret):
    return _http_post_form(_kc_token_url("eda"), {
        "grant_type": "client_credentials",
        "client_id": _SVC_CLIENT_ID,
        "client_secret": secret,
    }, get_ssl_context())


def get_eda_api_token(force=False, reprovision=False):
    """Acquire the service-account token (client_credentials). This SAME token drives both the
    EDA API and the Keycloak admin API (the SA holds _EDA_ROLE + _REALM_MGMT_ROLES).

    Runtime path (v26.4.1-4): authenticate with the PERSISTED client secret — NO KC master admin.
    KC master admin (keycloak-admin-secret) is used only as a fallback to (re)provision the client
    when there is no valid stored secret (first install, or the client was deleted/rotated). So once
    provisioned, the app keeps working even if the KC master-admin password later changes/goes stale.

    reprovision=True (v26.4.1-5) skips the stored-secret preference and forces a full
    _ensure_service_client pass — used by the 403 self-heal in eda_api_get/kc_admin_*: a valid
    stored secret with STRIPPED roles yields tokens that 403 everywhere, and only a full
    re-provision (which re-grants missing roles) can repair that."""
    now = time.time()
    if not force and _eda_api_token_cache[0] and now < _eda_api_token_cache[1] - 30:
        return _eda_api_token_cache[0]

    # Pin the Keycloak base BEFORE building any token URL. The stored-secret fast path must not
    # inherit the unprobed default: on deployments routing KC at /core/proxy/v1/identity (e.g.
    # the customer air-gap 26.4.1), the default candidate 404s — and a 404 is not a 400/401, so
    # without this line the app would never fall back and would wedge on every restart.
    _ensure_kc_base()

    resp = None
    # 1. Preferred: the stored/cached client secret — no KC admin involved.
    if not reprovision:
        secret = _svc_client_secret_cache[0]
        if not secret:
            secret, profile = _get_stored_client_secret()
            if secret and profile != _ROLE_PROFILE:
                # Credential predates the current role profile (e.g. an upgrade that
                # narrowed _EDA_ROLE). Re-provision once so the new grant — and the
                # revocation of the old one — actually happen; the fast path would
                # otherwise keep using the previously granted, broader identity.
                logger.info("Stored credential has role profile %r, expected %r — "
                            "re-provisioning %s once to apply the current roles",
                            profile, _ROLE_PROFILE, _SVC_CLIENT_ID)
                secret = None
                reprovision = True
        if secret:
            _svc_client_secret_cache[0] = secret
            try:
                resp = _client_credentials(secret)
            except urllib.error.HTTPError as e:
                if e.code in (400, 401):   # stored secret stale/revoked -> fall back to re-provision
                    logger.warning("Stored client secret rejected (HTTP %s) — re-provisioning %s",
                                   e.code, _SVC_CLIENT_ID)
                    _svc_client_secret_cache[0] = None
                    resp = None
                else:
                    raise
    # 2. Fallback: (re)provision via KC master admin, persist the new secret, then authenticate.
    if resp is None:
        admin_token = get_kc_admin_token()
        if reprovision:
            _svc_client_secret_cache[0] = None   # force the FULL ensure pass (incl. role re-grant)
        secret = _ensure_service_client(admin_token)
        resp = _client_credentials(secret)

    if not resp or "access_token" not in resp:
        raise RuntimeError("EDA API auth failed: no access_token")

    token = resp["access_token"]
    expires_in = resp.get("expires_in", 300)
    _eda_api_token_cache[0] = token
    _eda_api_token_cache[1] = now + expires_in
    logger.info("Service-account token acquired for %s (expires in %ds)", _SVC_CLIENT_ID, expires_in)
    return token


def invalidate_eda_token():
    """Called on HTTP 401 to force re-auth on next call. Drops the cached token AND the in-mem
    client secret so the next call re-reads the stored secret (and re-provisions if it's gone)."""
    _eda_api_token_cache[0] = None
    _eda_api_token_cache[1] = 0
    _svc_client_secret_cache[0] = None


def invalidate_kc_token():
    """Called on HTTP 401 to force re-auth on next call."""
    _kc_admin_token_cache[0] = None
    _kc_admin_token_cache[1] = 0


class AuthError(RuntimeError):
    """Failure while ACQUIRING a token, as opposed to a failure of the requested endpoint.

    Callers distinguish outcomes by HTTP status: transaction.py treats a 404 as proof that
    a transaction id does not exist. The auth stack can itself raise HTTPError(404) — a
    mis-routed Keycloak base, or a momentarily absent keycloak-admin-secret via
    k8s.read_secret — and up to v26.4.1-8 that escaped raw, so an auth outage was read as
    "this transaction does not exist": the id was skipped, the watermark advanced past it,
    and the record was lost silently while health still said ok. Wrapping token failures in
    a NON-HTTPError type makes them impossible to mistake for an endpoint 404; they
    propagate, the poll cycle fails loudly, and the watermark stays put for a clean retry.
    """


def _token(**kwargs):
    """Acquire a token, converting any auth-stack HTTP failure into AuthError."""
    try:
        return get_eda_api_token(**kwargs)
    except urllib.error.HTTPError as e:
        raise AuthError(f"EDA API token acquisition failed: HTTP {e.code} from {e.url}") from e


def eda_api_get(path_qs):
    """GET against the EDA API server. Retries once on 401 (stale token) and once on 403
    (role drift: a valid stored secret whose SA lost its roles — re-provision re-grants them)."""
    url = _EDA_API_BASE.rstrip("/") + "/" + path_qs.lstrip("/")
    token = _token()
    ssl_ctx = get_ssl_context()
    try:
        return http_json("GET", url,
                         {"Accept": "application/json", "Authorization": f"Bearer {token}"},
                         None, ssl_ctx)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            logger.warning("EDA API 401 — refreshing token and retrying")
            invalidate_eda_token()
            token = _token(force=True)
        elif e.code == 403:
            logger.warning("EDA API 403 — service account may have lost %s; re-provisioning %s "
                           "and retrying", _EDA_ROLE, _SVC_CLIENT_ID)
            invalidate_eda_token()
            token = _token(force=True, reprovision=True)
        else:
            raise
        return http_json("GET", url,
                         {"Accept": "application/json", "Authorization": f"Bearer {token}"},
                         None, ssl_ctx)


def kc_admin_get(path):
    """GET against the KC admin API, authenticated with the SERVICE-ACCOUNT token (it holds the
    realm-management roles). Runtime path needs no KC master admin. Retries once on 401 (stale
    token) and once on 403 (role drift -> re-provision re-grants the realm-management roles).

    NOTE: the URL is built AFTER the first token acquisition — get_eda_api_token() runs
    _ensure_kc_base(), and on the first call of the process _KC_BASE may change under us."""
    ssl_ctx = get_ssl_context()
    token = _token()                     # pins the KC base before we read _KC_BASE
    url = _KC_BASE + path
    try:
        return http_json("GET", url,
                         {"Authorization": f"Bearer {token}", "Accept": "application/json"},
                         None, ssl_ctx)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            logger.warning("KC admin 401 — refreshing service-account token and retrying")
            invalidate_eda_token()
            token = _token(force=True)
        elif e.code == 403:
            logger.warning("KC admin 403 — service account may have lost realm-management roles; "
                           "re-provisioning %s and retrying", _SVC_CLIENT_ID)
            invalidate_eda_token()
            token = _token(force=True, reprovision=True)
        else:
            raise
        return http_json("GET", url,
                         {"Authorization": f"Bearer {token}", "Accept": "application/json"},
                         None, ssl_ctx)


def kc_admin_put(path, body_dict):
    """PUT against the KC admin API with the service-account token (needs manage-realm).
    Same 401/403 retry semantics — and same URL-after-token ordering — as kc_admin_get."""
    ssl_ctx = get_ssl_context()
    data = json.dumps(body_dict).encode("utf-8")
    token = _token()                     # pins the KC base before we read _KC_BASE
    url = _KC_BASE + path

    def _put(tok):
        req = Request(url=url, data=data, method="PUT")
        req.add_header("Authorization", f"Bearer {tok}")
        req.add_header("Content-Type", "application/json")
        with urlopen(req, context=ssl_ctx, timeout=_TIMEOUT) as resp:
            resp.read()

    try:
        _put(token)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            logger.warning("KC admin PUT 401 — refreshing service-account token and retrying")
            invalidate_eda_token()
            _put(_token(force=True))
        elif e.code == 403:
            logger.warning("KC admin PUT 403 — service account may have lost manage-realm; "
                           "re-provisioning %s and retrying", _SVC_CLIENT_ID)
            invalidate_eda_token()
            _put(_token(force=True, reprovision=True))
        else:
            raise
