"""
Token management and TLS context for the EDA User Audit controller.

Acquires two tokens:
  1. KC admin token (master realm, admin-cli, password grant) from keycloak-admin-secret
  2. EDA API token (eda realm, password grant using eda-realm-auth-secret + fetched client secret)

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

# In-cluster base URL for KC and EDA API
_EDA_API_BASE = "https://eda-api.eda-system.svc"
_KC_BASE = _EDA_API_BASE + "/core/httpproxy/v1/keycloak"

# Token cache: (token_string, expiry_epoch)
_kc_admin_token_cache = [None, 0]
_eda_api_token_cache = [None, 0]
_eda_client_secret_cache = [None]

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


def _http_post_form(url, fields, ssl_ctx):
    data = urlencode(fields).encode("utf-8")
    req = Request(url=url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urlopen(req, context=ssl_ctx, timeout=_TIMEOUT) as resp:
        raw = resp.read()
        return json.loads(raw.decode("utf-8")) if raw else None


def http_json(method, url, headers, data, ssl_ctx):
    """Generic HTTP JSON request used by other modules."""
    req = Request(url=url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    with urlopen(req, context=ssl_ctx, timeout=_TIMEOUT) as resp:
        raw = resp.read()
        return json.loads(raw.decode("utf-8")) if raw else None


def _kc_token_url(realm):
    return f"{_KC_BASE}/realms/{realm}/protocol/openid-connect/token"


def get_kc_admin_token(force=False):
    """Acquire KC admin token from keycloak-admin-secret (master realm, admin-cli)."""
    now = time.time()
    if not force and _kc_admin_token_cache[0] and now < _kc_admin_token_cache[1] - 30:
        return _kc_admin_token_cache[0]

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


def _fetch_eda_client_secret(admin_token):
    """Fetch the 'eda' client secret via KC admin API (Approach B)."""
    if _eda_client_secret_cache[0]:
        return _eda_client_secret_cache[0]

    ssl_ctx = get_ssl_context()
    clients_url = f"{_KC_BASE}/admin/realms/eda/clients?clientId=eda"
    clients = http_json("GET", clients_url,
                        {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
                        None, ssl_ctx) or []
    kc_id = next((c.get("id") for c in clients if c.get("clientId") == "eda"), None)
    if not kc_id:
        raise RuntimeError("Client 'eda' not found in realm 'eda'")

    secret_url = f"{_KC_BASE}/admin/realms/eda/clients/{kc_id}/client-secret"
    secret_json = http_json("GET", secret_url,
                            {"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
                            None, ssl_ctx) or {}
    val = secret_json.get("value") or secret_json.get("secret")
    if not val:
        raise RuntimeError("Failed to fetch eda client secret")

    _eda_client_secret_cache[0] = val
    return val


def get_eda_api_token(force=False):
    """Acquire EDA API token using password grant (Approach B)."""
    now = time.time()
    if not force and _eda_api_token_cache[0] and now < _eda_api_token_cache[1] - 30:
        return _eda_api_token_cache[0]

    admin_token = get_kc_admin_token()
    client_secret = _fetch_eda_client_secret(admin_token)

    secret = k8s.read_secret("eda-realm-auth-secret", _NAMESPACE)
    username = secret.get("username")
    password = secret.get("password")
    if not username or not password:
        raise RuntimeError("eda-realm-auth-secret missing username or password")

    resp = _http_post_form(_kc_token_url("eda"), {
        "grant_type": "password",
        "client_id": "eda",
        "client_secret": client_secret,
        "scope": "openid",
        "username": username,
        "password": password,
    }, get_ssl_context())

    if not resp or "access_token" not in resp:
        raise RuntimeError("EDA API auth failed: no access_token")

    token = resp["access_token"]
    expires_in = resp.get("expires_in", 300)
    _eda_api_token_cache[0] = token
    _eda_api_token_cache[1] = now + expires_in
    logger.info("EDA API token acquired (expires in %ds)", expires_in)
    return token


def invalidate_eda_token():
    """Called on HTTP 401 to force re-auth on next call."""
    _eda_api_token_cache[0] = None
    _eda_api_token_cache[1] = 0
    _eda_client_secret_cache[0] = None


def invalidate_kc_token():
    """Called on HTTP 401 to force re-auth on next call."""
    _kc_admin_token_cache[0] = None
    _kc_admin_token_cache[1] = 0


def eda_api_get(path_qs):
    """GET against the EDA API server with automatic 401 retry."""
    url = _EDA_API_BASE.rstrip("/") + "/" + path_qs.lstrip("/")
    token = get_eda_api_token()
    ssl_ctx = get_ssl_context()
    try:
        return http_json("GET", url,
                         {"Accept": "application/json", "Authorization": f"Bearer {token}"},
                         None, ssl_ctx)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            logger.warning("EDA API 401 — refreshing token and retrying")
            invalidate_eda_token()
            token = get_eda_api_token(force=True)
            return http_json("GET", url,
                             {"Accept": "application/json", "Authorization": f"Bearer {token}"},
                             None, ssl_ctx)
        raise


def kc_admin_get(path):
    """GET against KC admin API with automatic 401 retry."""
    url = _KC_BASE + path
    token = get_kc_admin_token()
    ssl_ctx = get_ssl_context()
    try:
        return http_json("GET", url,
                         {"Authorization": f"Bearer {token}", "Accept": "application/json"},
                         None, ssl_ctx)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            logger.warning("KC admin 401 — refreshing token and retrying")
            invalidate_kc_token()
            token = get_kc_admin_token(force=True)
            return http_json("GET", url,
                             {"Authorization": f"Bearer {token}", "Accept": "application/json"},
                             None, ssl_ctx)
        raise


def kc_admin_put(path, body_dict):
    """PUT against KC admin API."""
    url = _KC_BASE + path
    token = get_kc_admin_token()
    ssl_ctx = get_ssl_context()
    data = json.dumps(body_dict).encode("utf-8")
    req = Request(url=url, data=data, method="PUT")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    with urlopen(req, context=ssl_ctx, timeout=_TIMEOUT) as resp:
        resp.read()
