"""
Transaction polling: summary pagination, execution API node discovery, resource diffs, node config diffs.
Ported from edalogger.py lines 715-1141 + 810-1003 with execution API replacing node guessing.
"""

import difflib
import json
import logging
import re
import urllib.error
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode

import auth
import keycloak_events as kc

logger = logging.getLogger("txn")


# ----------------------------- Formatting (from edalogger.py 734-808) -----------------

def format_change_line(tx_ts_display, tx_id, tx_user, user_ip, modified, namespace, change):
    mod_val = (modified or "").strip() or "none"
    ns_val = (namespace or "").strip() or "none"

    def _decorate(val):
        if not val:
            return val
        if val.startswith("+") or val.startswith("-"):
            return f"({val[0]}){val[1:]}"
        return val

    return (
        f"{tx_ts_display} | Event=Transaction-{tx_id} | User={tx_user} | IPADDR={user_ip} | "
        f"Modified={mod_val} | Namespace={ns_val} | {_decorate(change)}"
    )


def format_status_line(tx_ts_display, tx_id, tx_user, user_ip, message):
    return f"{tx_ts_display} | Event=Transaction-{tx_id} | User={tx_user} | IPADDR={user_ip} | Modified=none | {message}"


def format_resource_event(tx_ts_display, tx_id, tx_user, user_ip, namespace, message):
    ns_val = (namespace or "").strip() or "none"
    return (
        f"{tx_ts_display} | Event=Transaction-{tx_id} | User={tx_user} | IPADDR={user_ip} | "
        f"Modified=EDA | Namespace={ns_val} | {message}"
    )


def _resource_label(group, kind):
    grp = (group or "").lower()
    prefix = "Bootstrap " if grp.startswith("bootstrap.eda.nokia.com") else ""
    if kind:
        return f"{prefix}{kind}"
    fallback = (group or "").split(".")[0] or "Resource"
    return f"{prefix}{fallback.capitalize()}"


def _resource_namespace(kind, namespace, name):
    ns_val = (namespace or "").strip()
    if ns_val:
        return ns_val
    if (kind or "").lower() == "namespace" and name:
        return name
    return "none"


# ----------------------------- Flattening & diff (from edalogger.py 810-1003) ---------

_key_val_re = re.compile(r"^\s*(?P<key>[^=\s].*?)(?:\s*=\s*|\s+)(?P<val>.+?)\s*$")


def _dot_or_space_line_to_flat(line):
    m = _key_val_re.match(line)
    if not m:
        return None
    key, val = m.group("key"), m.group("val")
    key = key.replace(".", "/")
    key = re.sub(r"\[(\d+)\]", r"/\1", key)
    key = re.sub(r"/+", "/", key).strip("/")
    return f"{key} {val}"


def _flatten_json(obj, prefix=""):
    lines = []
    if isinstance(obj, dict):
        for k in sorted(obj.keys()):
            newp = f"{prefix}/{k}" if prefix else str(k)
            lines.extend(_flatten_json(obj[k], newp))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            newp = f"{prefix}/{i}" if prefix else str(i)
            lines.extend(_flatten_json(v, newp))
    else:
        val = json.dumps(obj, ensure_ascii=False, sort_keys=True)
        lines.append(f"{prefix} {val}")
    return lines


def _flatten_curly_dsl(text):
    lines = text.splitlines()
    path_stack = []
    block_depth = []
    out = []
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        s = raw.strip()
        i += 1
        if not s:
            continue
        if s == "}" or s.startswith("}"):
            if block_depth:
                pops = block_depth.pop()
                for _ in range(pops):
                    if path_stack:
                        path_stack.pop()
            continue
        if s.endswith("{"):
            content = s[:-1].strip()
            toks = content.split() if content else []
            for t in toks:
                path_stack.append(t)
            block_depth.append(len(toks))
            continue
        m1 = re.match(r"^(?P<k>\S+)\s*\[\s*(?P<vals>.*?)\s*\]\s*$", s)
        if m1:
            k = m1.group("k")
            vals = m1.group("vals").strip()
            if vals:
                inner = [v for v in re.split(r"[,\s]+", vals) if v]
                val = "[" + ", ".join(inner) + "]"
            else:
                val = "[]"
            out.append(f"{'/'.join(path_stack + [k])} {val}")
            continue
        if s.endswith("["):
            k = s[:-1].strip()
            inner_vals = []
            while i < n:
                inner = lines[i].strip()
                i += 1
                if inner == "]" or inner.endswith("]"):
                    break
                if inner:
                    inner_vals.append(inner.rstrip(","))
            tokens = []
            for itm in inner_vals:
                if (itm.startswith('"') and itm.endswith('"')) or (itm.startswith("'") and itm.endswith("'")):
                    tokens.append(itm)
                else:
                    tokens += [t for t in re.split(r"[,\s]+", itm) if t]
            val = "[" + ", ".join(tokens) + "]"
            out.append(f"{'/'.join(path_stack + [k])} {val}")
            continue
        parts = s.split(None, 1)
        if len(parts) == 2:
            k, v = parts[0], parts[1]
            out.append(f"{'/'.join(path_stack + [k])} {v}")
            continue
        out.append(f"{'/'.join(path_stack + [s])}")
    return out


def _normalize_text_block(s):
    t = (s or "").strip()
    if not t:
        return []
    try:
        obj = json.loads(t)
        return _flatten_json(obj)
    except Exception:
        pass
    if "{" in t or "}" in t:
        return _flatten_curly_dsl(t)
    out = []
    for raw in t.splitlines():
        flat = _dot_or_space_line_to_flat(raw)
        out.append(flat if flat is not None else raw.strip())
    return out


def ndiff_delta(before, after):
    b = _normalize_text_block(before)
    a = _normalize_text_block(after)
    diff = list(difflib.ndiff(b, a))
    out = []
    seen_pairs = set()
    seen_singles = set()
    i = 0
    while i < len(diff):
        d = diff[i]
        if d.startswith("- "):
            minus = "-" + d[2:]
            if i + 1 < len(diff) and diff[i + 1].startswith("+ "):
                plus = "+" + diff[i + 1][2:]
                pair = (minus, plus)
                if pair not in seen_pairs:
                    out.extend([minus, plus])
                    seen_pairs.add(pair)
                i += 2
            else:
                if minus not in seen_singles:
                    out.append(minus)
                    seen_singles.add(minus)
                i += 1
        elif d.startswith("+ "):
            plus = "+" + d[2:]
            if plus not in seen_singles:
                out.append(plus)
                seen_singles.add(plus)
            i += 1
        else:
            i += 1
    return out


# ----------------------------- Resource diffs (from edalogger.py 1017-1078) -----------

def _collect_resource_change_lines(tx_id, tx_user, tx_ts_display, user_ip):
    lines = []
    namespaces = set()
    try:
        input_json = auth.eda_api_get(f"core/transaction/v2/result/inputresources/{tx_id}") or {}
    except urllib.error.HTTPError as e:
        if e.code == 400:
            return lines, namespaces
        logger.warning("inputresources fetch failed for tx %d: %s", tx_id, e)
        return lines, namespaces
    except Exception as e:
        logger.warning("inputresources fetch failed for tx %d: %s", tx_id, e)
        return lines, namespaces

    resources = input_json.get("inputCrs") or []
    for r in resources:
        name_info = r.get("name") or {}
        gvk = name_info.get("gvk") or {}
        res_name = name_info.get("name")
        group = gvk.get("group")
        version = gvk.get("version")
        kind = gvk.get("kind")
        namespace = name_info.get("namespace", "")
        if not (res_name and group and version and kind):
            continue

        qs = (
            f"core/transaction/v2/result/diffs/resource/{tx_id}"
            f"?group={quote(str(group))}&version={quote(str(version))}&kind={quote(str(kind))}&name={quote(str(res_name))}"
        )
        if namespace:
            qs += f"&namespace={quote(str(namespace))}"

        diff_json = {}
        try:
            diff_json = auth.eda_api_get(qs) or {}
        except Exception as e:
            logger.warning("resource diff failed for tx %d (%s/%s/%s): %s", tx_id, group, kind, res_name, e)

        before = ((diff_json.get("before") or {}).get("data")) if isinstance(diff_json, dict) else None
        after = ((diff_json.get("after") or {}).get("data")) if isinstance(diff_json, dict) else None
        is_delete = bool(r.get("isDelete"))

        if is_delete or (before and not after):
            action = "deleted"
        elif after and not before:
            action = "created"
        else:
            action = "updated"

        label = _resource_label(group, kind)
        ns_for_line = _resource_namespace(kind, namespace, res_name)
        namespaces.add(ns_for_line if ns_for_line else "")
        if action == "created":
            msg = f"{label} resource named {res_name} has been created."
        elif action == "deleted":
            msg = f"{label} resource named {res_name} has been deleted."
        else:
            msg = f"{label} resource named {res_name} has been modified."

        lines.append(format_resource_event(tx_ts_display, tx_id, tx_user, user_ip, ns_for_line, msg))
    return lines, namespaces


# ----------------------------- Node config diffs (MAJOR CHANGE: execution API) --------

def _get_execution_nodes(tx_id):
    """Get nodes with config changes from the execution API.

    Returns a list of (node_name, node_namespace) tuples, or None on failure.
    The API returns objects like {"name": "leaf1", "namespace": "eda", "errors": null}.
    """
    try:
        exec_json = auth.eda_api_get(f"core/transaction/v2/result/execution/{tx_id}") or {}
        raw_nodes = exec_json.get("nodesWithConfigChanges") or []
        nodes = []
        for n in raw_nodes:
            if isinstance(n, dict):
                name = n.get("name")
                ns = n.get("namespace", "")
                if name:
                    nodes.append((str(name), str(ns) if ns else ""))
            elif isinstance(n, str):
                nodes.append((n, ""))
        return nodes
    except Exception as e:
        logger.warning("Execution API failed for transaction %d — skipping node config diffs: %s", tx_id, e)
        return None


def _collect_nodecfg_lines(tx_id, tx_user, tx_ts_display, user_ip, namespaces, nodes):
    """Collect node config diff lines.

    Args:
        nodes: list of (node_name, node_namespace) tuples from _get_execution_nodes.
    """
    lines = []
    extra_ns = set([ns for ns in namespaces if ns] + ["eda", "eda-telemetry", "default", ""])
    for node_name, node_ns in nodes:
        # Prioritize the namespace from execution API, then fall back to candidates
        ns_candidates = [node_ns] if node_ns else []
        ns_candidates.extend(ns for ns in extra_ns if ns != node_ns)
        tried = set()
        for ns in ns_candidates:
            if ns in tried:
                continue
            tried.add(ns)
            qs = f"core/transaction/v2/result/diffs/nodecfg/{tx_id}?node={quote(str(node_name))}"
            if ns:
                qs += f"&namespace={quote(str(ns))}"
            try:
                diff_json = auth.eda_api_get(qs) or {}
            except Exception:
                continue
            if diff_json.get("dataUnavailable") is True:
                continue
            before = ((diff_json.get("before") or {}).get("data")) or ""
            after = ((diff_json.get("after") or {}).get("data")) or ""
            delta = ndiff_delta(before, after)
            if not delta:
                continue
            for change in delta:
                lines.append(format_change_line(tx_ts_display, tx_id, tx_user, user_ip, node_name, ns, change))
    return lines


# ----------------------------- Transaction collection (adapted from 1114-1141) --------

def collect_transaction_lines(tx_id, tx_user, tx_ts_display, tx_iso, user_ip):
    resource_lines, resource_namespaces = _collect_resource_change_lines(tx_id, tx_user, tx_ts_display, user_ip)

    # Use execution API for node discovery instead of guessing
    nodes = _get_execution_nodes(tx_id)
    node_lines = []
    if nodes is not None and nodes:
        node_lines = _collect_nodecfg_lines(tx_id, tx_user, tx_ts_display, user_ip, resource_namespaces, nodes)

    log_lines = []
    log_lines.extend(node_lines)
    log_lines.extend(resource_lines)

    if not log_lines:
        log_lines.append(format_change_line(tx_ts_display, tx_id, tx_user, user_ip, "none", "", "(no config changes)"))
    return log_lines


# ----------------------------- Poll transactions (adapted from run_once) ---------------

def poll_transactions(last_tx_id, event_window_seconds=3600):
    """
    Poll for new transactions starting from last_tx_id+1.
    Returns (lines_by_month, last_processed_id, last_tx_iso, tx_count).
    """
    start_id = (last_tx_id + 1) if last_tx_id is not None else 1
    max_missing = 20
    missing = 0
    last_processed = None
    last_tx_iso = None
    txn_lines_by_month = {}
    tx_count = 0

    tx_id = start_id
    while missing < max_missing:
        try:
            summary = auth.eda_api_get(f"core/transaction/v2/result/summary/{tx_id}")
        except Exception:
            summary = None

        if not summary:
            missing += 1
            tx_id += 1
            continue

        missing = 0
        tx_user = summary.get("username", "")
        tx_time = summary.get("lastChangeTimestamp", "")
        tx_success = bool(summary.get("success"))
        tx_dry_run = bool(summary.get("dryRun"))
        tx_state = summary.get("state", "")
        tx_iso, tx_ts_display, tx_ms = kc._normalize_iso_ts(tx_time)

        user_ip = "N/A"
        try:
            hit_ip = kc.get_user_login_ip_near_commit(tx_user, tx_time, event_window_seconds)
            if hit_ip:
                user_ip = hit_ip
        except Exception as e:
            logger.warning("KC IP lookup failed for tx %d: %s", tx_id, e)

        if tx_dry_run:
            log_lines = [format_status_line(tx_ts_display, tx_id, tx_user, user_ip,
                                            "Dryrun , no changes were made on the system or the nodes.")]
        elif not tx_success or tx_state != "complete":
            log_lines = [format_status_line(tx_ts_display, tx_id, tx_user, user_ip,
                                            "Failed transaction attempt, no changes were made on the system or the nodes.")]
        else:
            log_lines = collect_transaction_lines(tx_id, tx_user, tx_ts_display, tx_iso, user_ip)

        month = kc._month_key(tx_iso)
        txn_lines_by_month.setdefault(month, []).extend((tx_ms, line) for line in log_lines)
        last_processed = tx_id
        last_tx_iso = tx_iso
        tx_count += 1
        tx_id += 1

    if tx_count:
        logger.info("Processing %d new transactions (IDs %d-%d)", tx_count, start_id, last_processed)
    return txn_lines_by_month, last_processed, last_tx_iso, tx_count


def discover_current_watermark():
    """On first run, discover the highest transaction ID from the summary API."""
    try:
        summary = auth.eda_api_get("core/transaction/v2/result/summary?page=0&size=1") or {}
        results = summary.get("results") or []
        if results:
            return int(results[0].get("id", 0))
        return 0
    except Exception as e:
        logger.warning("Failed to discover transaction watermark: %s", e)
        return 0
