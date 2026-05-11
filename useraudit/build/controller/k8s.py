"""
Raw Kubernetes API client using urllib.
Reads the in-cluster service account token; uses the K8s CA for TLS.
All requests have a 30-second timeout.
"""

import json
import logging
import ssl
import urllib.error
from base64 import b64decode
from urllib.parse import quote
from urllib.request import Request, urlopen

logger = logging.getLogger("k8s")

_K8S_BASE = "https://kubernetes.default.svc"
_SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
_TIMEOUT = 30


def _ssl_ctx():
    ctx = ssl.create_default_context(cafile=_SA_CA_PATH)
    return ctx


def _token():
    with open(_SA_TOKEN_PATH) as f:
        return f.read().strip()


def _request(method, path, body=None):
    url = _K8S_BASE + path
    data = json.dumps(body).encode("utf-8") if body else None
    req = Request(url=url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {_token()}")
    req.add_header("Accept", "application/json")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, context=_ssl_ctx(), timeout=_TIMEOUT) as resp:
            raw = resp.read()
            return json.loads(raw.decode("utf-8")) if raw else None
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        logger.warning("K8s API %s %s -> HTTP %d: %s", method, path, e.code, body_text)
        raise


def read_secret(name, namespace="eda-system"):
    path = f"/api/v1/namespaces/{quote(namespace, safe='')}/secrets/{quote(name, safe='')}"
    obj = _request("GET", path)
    data = obj.get("data", {})
    return {k: b64decode(v).decode("utf-8") for k, v in data.items()}


def read_configmap(name, namespace="eda-system"):
    path = f"/api/v1/namespaces/{quote(namespace, safe='')}/configmaps/{quote(name, safe='')}"
    try:
        return _request("GET", path)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def create_configmap(name, namespace, data_dict):
    path = f"/api/v1/namespaces/{quote(namespace, safe='')}/configmaps"
    body = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace},
        "data": data_dict,
    }
    return _request("POST", path, body)


def update_configmap(name, namespace, data_dict, resource_version):
    path = f"/api/v1/namespaces/{quote(namespace, safe='')}/configmaps/{quote(name, safe='')}"
    body = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace, "resourceVersion": resource_version},
        "data": data_dict,
    }
    return _request("PUT", path, body)


def read_cr(group, version, plural, name):
    path = f"/apis/{group}/{version}/{plural}/{quote(name, safe='')}"
    try:
        return _request("GET", path)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def create_cr(group, version, plural, body):
    path = f"/apis/{group}/{version}/{plural}"
    return _request("POST", path, body)


def update_cr_status(group, version, plural, name, full_obj):
    path = f"/apis/{group}/{version}/{plural}/{quote(name, safe='')}/status"
    return _request("PUT", path, full_obj)
