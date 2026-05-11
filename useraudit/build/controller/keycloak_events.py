"""
Keycloak event polling: login/logout events, admin events, IP resolution, user/group resolution.
Ported from edalogger.py lines 175-665 with adaptations for controller mode.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, quote

import auth

logger = logging.getLogger("kc")

# ----------------------------- Timestamp utilities (from edalogger.py 177-220) --------

def _parse_iso_datetime(ts: str) -> Optional[datetime]:
    ts = (ts or "").strip()
    if not ts:
        return None
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _iso_to_epoch_ms(ts: str) -> int:
    ts = (ts or "").strip()
    if not ts:
        return 0
    dt = _parse_iso_datetime(ts)
    if not dt:
        return 0
    return int(dt.timestamp() * 1000)


def _dt_to_iso_local(dt: datetime) -> Tuple[str, datetime]:
    dt_local = dt.astimezone()
    iso = dt_local.isoformat(timespec="seconds")
    return iso, dt_local


def _dt_to_display(dt: datetime) -> str:
    _, dt_local = _dt_to_iso_local(dt)
    tzname = dt_local.tzname() or "local"
    return f"{dt_local.strftime('%Y-%m-%dT%H:%M:%S')} {tzname}"


def _normalize_iso_ts(ts: str) -> Tuple[str, str, int]:
    dt = _parse_iso_datetime(ts) or datetime.now(timezone.utc)
    iso_local, _ = _dt_to_iso_local(dt)
    return iso_local, _dt_to_display(dt), int(dt.timestamp() * 1000)


def _iso_from_epoch_ms(ms: int) -> str:
    try:
        dt = datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc)
        iso_local, _ = _dt_to_iso_local(dt)
        return iso_local
    except Exception:
        return "unknown-time"


def _month_key(ts: str) -> str:
    dt = _parse_iso_datetime(ts)
    if not dt:
        return "unknown-month"
    return dt.strftime("%Y-%m")


# ----------------------------- KC Event auto-enablement (NEW) -------------------------

def ensure_events_enabled():
    """Verify KC events are enabled on the eda realm; re-enable if needed (read-modify-write)."""
    try:
        realm = auth.kc_admin_get("/admin/realms/eda")
        if not realm:
            logger.warning("Could not read eda realm config")
            return
        needs_update = False
        for key in ("eventsEnabled", "adminEventsEnabled", "adminEventsDetailsEnabled"):
            if not realm.get(key):
                needs_update = True
                break
        if not needs_update:
            return
        realm["eventsEnabled"] = True
        realm["adminEventsEnabled"] = True
        realm["adminEventsDetailsEnabled"] = True
        realm["eventsExpiration"] = 604800  # 7 days
        auth.kc_admin_put("/admin/realms/eda", realm)
        logger.info("KC events re-enabled on eda realm")
    except Exception as e:
        logger.warning("Failed to ensure KC events enabled: %s", e)


# ----------------------------- Event fetching (from edalogger.py 265-314) -------------

_ALLOWED_LOGIN_EVENTS = {"LOGIN", "LOGOUT"}
_ALLOWED_ADMIN_RESOURCE_TYPES = {"USER", "GROUP", "CLIENT_ROLE", "USER_FEDERATION", "COMPONENT", "REALM_ROLE", "REALM"}
_ALLOWED_ADMIN_OPS = {"CREATE", "UPDATE", "DELETE"}


def _kc_fetch_login_logout_events(page_size=500) -> List[Dict]:
    params = [("max", page_size)]
    for t in sorted(_ALLOWED_LOGIN_EVENTS):
        params.append(("type", t))
    path = f"/admin/realms/eda/events?{urlencode(params, doseq=True)}"
    return auth.kc_admin_get(path) or []


def _kc_fetch_admin_events(page_size=500) -> List[Dict]:
    base_params = [("max", page_size)]
    for op in sorted(_ALLOWED_ADMIN_OPS):
        base_params.append(("operationTypes", op))

    def _do(params):
        path = f"/admin/realms/eda/admin-events?{urlencode(params, doseq=True)}"
        return auth.kc_admin_get(path) or []

    try:
        params = list(base_params)
        for rt in sorted(_ALLOWED_ADMIN_RESOURCE_TYPES):
            params.append(("resourceTypes", rt))
        return _do(params)
    except Exception:
        try:
            return _do(base_params)
        except Exception:
            return []


# ----------------------------- User/group resolution (from edalogger.py 222-354) ------

def _kc_find_user_id(username: str) -> Optional[str]:
    users = auth.kc_admin_get(f"/admin/realms/eda/users?username={quote(str(username))}&exact=true") or []
    if not users:
        users = auth.kc_admin_get(f"/admin/realms/eda/users?search={quote(str(username))}") or []
        users = [u for u in users if (u.get("username") or "").lower() == username.lower()]
    return users[0].get("id") if users else None


def _kc_resolve_username_by_id(user_id: str, cache: Dict[str, Optional[str]]) -> Optional[str]:
    if not user_id:
        return None
    if user_id in cache:
        return cache[user_id]
    try:
        j = auth.kc_admin_get(f"/admin/realms/eda/users/{quote(str(user_id))}") or {}
        username = j.get("username") or j.get("email") or j.get("id")
    except Exception:
        username = None
    cache[user_id] = username
    return username


def _kc_resolve_groupname_by_id(group_id: str, cache: Dict[str, Optional[str]]) -> Optional[str]:
    if not group_id:
        return None
    if group_id in cache:
        return cache[group_id]
    try:
        j = auth.kc_admin_get(f"/admin/realms/eda/groups/{quote(group_id)}") or {}
        name = j.get("name") or j.get("id")
    except Exception:
        name = None
    cache[group_id] = name
    return name


def get_user_login_ip_near_commit(username: str, commit_iso_ts: str, event_window_seconds: int = 3600) -> Optional[str]:
    user_id = _kc_find_user_id(username)
    if not user_id:
        return None
    commit_ms = _iso_to_epoch_ms(commit_iso_ts)
    window_ms = max(1, event_window_seconds) * 1000
    events = auth.kc_admin_get(f"/admin/realms/eda/events?{urlencode({'type': 'LOGIN', 'user': user_id, 'max': 100})}") or []
    best_ip = None
    best_diff = None
    for ev in events:
        ev_time = ev.get("time")
        ip = ev.get("ipAddress")
        if ev_time is None or not ip:
            continue
        # Only consider real browser code-flow logins (clientId="auth").
        # Skip service-to-service password grants (clientId="eda") — those include
        # the useraudit controller's own admin token-refresh logins, whose source IP is
        # the controller pod, not the user.
        if ev.get("clientId") != "auth":
            continue
        diff = abs(int(ev_time) - commit_ms)
        if diff <= window_ms and (best_diff is None or diff < best_diff or
                                  (diff == best_diff and int(ev_time) <= commit_ms)):
            best_ip = ip
            best_diff = diff
    return best_ip


# ----------------------------- Event filtering (from edalogger.py 357-434) ------------

def _extract_user_target(ev: Dict) -> Tuple[Optional[str], Optional[str]]:
    rt = (ev.get("resourceType") or "").upper()
    if rt != "USER":
        return None, None
    resource_path = ev.get("resourcePath") or ""
    target_id = None
    if resource_path.lower().startswith("users/"):
        parts = resource_path.split("/")
        if len(parts) >= 2:
            target_id = parts[1]
    target_username = None
    rep = ev.get("representation")
    if rep:
        try:
            rep_obj = json.loads(rep)
            target_username = rep_obj.get("username") or rep_obj.get("email")
            target_id = rep_obj.get("id") or target_id
        except Exception:
            pass
    return target_id, target_username


def _extract_group_target(ev: Dict) -> Tuple[Optional[str], Optional[str]]:
    rt = (ev.get("resourceType") or "").upper()
    if rt != "GROUP":
        return None, None
    resource_path = ev.get("resourcePath") or ""
    target_id = None
    if resource_path.lower().startswith("groups/"):
        parts = resource_path.split("/")
        if len(parts) >= 2:
            target_id = parts[1]
    target_name = None
    rep = ev.get("representation")
    if rep:
        try:
            rep_obj = json.loads(rep)
            target_name = rep_obj.get("name") or rep_obj.get("id")
            target_id = rep_obj.get("id") or target_id
        except Exception:
            pass
    return target_id, target_name


def _is_ldap_provider_event(ev: Dict) -> bool:
    rt = (ev.get("resourceType") or "").upper()
    if rt not in {"USER_FEDERATION", "COMPONENT"}:
        return False
    rep = ev.get("representation")
    if rep:
        try:
            rep_obj = json.loads(rep)
            provider_id = (rep_obj.get("providerId") or rep_obj.get("provider") or "").lower()
            if provider_id == "ldap":
                return True
        except Exception:
            pass
    path = (ev.get("resourcePath") or "").lower()
    return "ldap" in path


def _filter_admin_events(admin_events: List[Dict]) -> List[Dict]:
    out = []
    for ev in admin_events:
        rt = (ev.get("resourceType") or "").upper()
        op = (ev.get("operationType") or "").upper()
        if op not in _ALLOWED_ADMIN_OPS:
            continue
        if rt == "REALM_ROLE":
            continue
        if rt in {"USER", "GROUP", "CLIENT_ROLE", "REALM"}:
            out.append(ev)
        elif rt in {"USER_FEDERATION", "COMPONENT"}:
            if _is_ldap_provider_event(ev):
                out.append(ev)
    return out


# ----------------------------- Event formatting (from edalogger.py 437-580) -----------

def _format_login_logout_line(ev: Dict, user_lookup=None) -> Optional[Tuple[int, str, str]]:
    try:
        ts_ms = int(ev.get("time") or 0)
    except Exception:
        return None
    if ts_ms <= 0:
        return None
    event_type = (ev.get("type") or "LOGIN").upper()
    if event_type not in _ALLOWED_LOGIN_EVENTS:
        return None
    details = ev.get("details") or {}
    user_id = ev.get("userId") or details.get("userId")
    user = details.get("username") or ev.get("username")
    if not user and user_lookup and user_id:
        resolved = user_lookup(user_id)
        if resolved:
            user = resolved
    if not user:
        user = user_id or "-"
    ip = ev.get("ipAddress") or "-"
    client = (ev.get("clientId") or "").strip()
    client_lower = client.lower()
    if client_lower == "eda":
        return None
    iso = _iso_from_epoch_ms(ts_ms)
    display_ts = _dt_to_display(datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc))
    if client_lower == "auth":
        if event_type == "LOGIN":
            line = f"{display_ts} | Event=EDA-Login | User={user} | IPADDR={ip} | The user signed-in to the EDA GUI."
        else:
            line = f"{display_ts} | Event=EDA-Logout | User={user} | IPADDR={ip} | The user signed-out of the EDA GUI."
    else:
        return None
    return ts_ms, iso, line


def _format_admin_event_line(ev: Dict, user_lookup=None,
                             user_target_cache=None, group_target_cache=None,
                             group_lookup=None) -> Optional[Tuple[int, str, str]]:
    try:
        ts_ms = int(ev.get("time") or 0)
    except Exception:
        return None
    if ts_ms <= 0:
        return None
    rt = (ev.get("resourceType") or "UNKNOWN").upper()
    op = (ev.get("operationType") or "UNKNOWN").upper()
    if op not in _ALLOWED_ADMIN_OPS:
        return None
    if rt not in _ALLOWED_ADMIN_RESOURCE_TYPES:
        return None
    if rt in {"USER_FEDERATION", "COMPONENT"} and not _is_ldap_provider_event(ev):
        return None

    auth_details = ev.get("authDetails") or {}
    details = ev.get("details") or {}
    actor = auth_details.get("username")
    actor_id = auth_details.get("userId")
    details_actor_id = details.get("userId")
    resolved_actor = None
    if user_lookup:
        for uid in (actor_id, details_actor_id):
            if uid:
                resolved_actor = user_lookup(uid)
                if resolved_actor:
                    break
    if not actor or actor.startswith("service-account-") or (resolved_actor and actor in {actor_id, details_actor_id}):
        actor = resolved_actor or actor or actor_id or details_actor_id or "-"
    ip = auth_details.get("ipAddress") or "-"
    resource_path = ev.get("resourcePath") or "-"

    iso = _iso_from_epoch_ms(ts_ms)
    display_ts = _dt_to_display(datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc))
    line = None

    if rt == "USER":
        target_id, target_username = _extract_user_target(ev)
        if user_target_cache is not None and target_id and target_username:
            user_target_cache.setdefault(target_id, target_username)
        if not target_username and target_id:
            if user_target_cache is not None and target_id in user_target_cache:
                target_username = user_target_cache.get(target_id)
            if not target_username and user_lookup:
                resolved_target = user_lookup(target_id)
                if resolved_target:
                    target_username = resolved_target
                    if user_target_cache is not None:
                        user_target_cache[target_id] = resolved_target
        if user_target_cache is not None and target_id and target_username:
            user_target_cache[target_id] = target_username
        target_label = target_username or target_id or "unknown-user"
        action_word = {"CREATE": "created", "DELETE": "deleted"}.get(op, "updated")
        line = (f"{display_ts} | Event=USER-{op} | User={actor} | IPADDR={ip} | "
                f"User {target_label} has been {action_word}.")
    elif rt == "GROUP":
        target_id, target_name = _extract_group_target(ev)
        if group_target_cache is not None and target_id and target_name:
            group_target_cache.setdefault(target_id, target_name)
        if not target_name and target_id:
            if group_target_cache is not None and target_id in group_target_cache:
                target_name = group_target_cache.get(target_id)
            if not target_name and group_lookup:
                resolved_group = group_lookup(target_id)
                if resolved_group:
                    target_name = resolved_group
                    if group_target_cache is not None:
                        group_target_cache[target_id] = resolved_group
        if group_target_cache is not None and target_id and target_name:
            group_target_cache[target_id] = target_name
        target_label = target_name or target_id or "unknown-group"
        action_word = {"CREATE": "created", "DELETE": "deleted"}.get(op, "updated")
        line = (f"{display_ts} | Event=USERGROUP-{op} | User={actor} | IPADDR={ip} | "
                f"UserGroup {target_label} has been {action_word}.")
    elif rt == "REALM":
        line = (f"{display_ts} | Event=REALM-{op} | User={actor} | IPADDR={ip} | "
                f"Password policy has been modified.")
    else:
        descriptor = f"LDAP-{op}" if rt in {"USER_FEDERATION", "COMPONENT"} else f"{rt}-{op}"
        line = (f"{display_ts} | Event=Keycloak-{descriptor} | User={actor} | IPADDR={ip} | "
                f"Resource={resource_path}")

    return ts_ms, iso, line


# ----------------------------- Main collection (from edalogger.py 583-665) ------------

def collect_keycloak_user_logs(last_event_ms: int,
                               user_id_map: Optional[Dict[str, str]],
                               group_id_map: Optional[Dict[str, str]]) -> Tuple[int, int, Dict[str, List[Tuple[int, str]]], Dict[str, str], Dict[str, str]]:
    """
    Fetch KC user/admin events; returns (count, max_seen_ms, lines_by_month, updated_user_map, updated_group_map).
    """
    user_cache: Dict[str, Optional[str]] = {}
    base_user_map = dict(user_id_map or {})
    base_group_map = dict(group_id_map or {})
    user_target_cache: Dict[str, Optional[str]] = dict(base_user_map)
    group_target_cache: Dict[str, Optional[str]] = dict(base_group_map)

    login_events = []
    admin_events_raw = []

    try:
        login_events = _kc_fetch_login_logout_events()
    except Exception as e:
        logger.warning("KC login/logout events fetch failed: %s", e)

    try:
        admin_events_raw = _kc_fetch_admin_events()
    except Exception as e:
        logger.warning("KC admin events fetch failed: %s", e)

    admin_events = _filter_admin_events(admin_events_raw)
    for ev in admin_events:
        tid, tuser = _extract_user_target(ev)
        if tid and tuser:
            user_target_cache.setdefault(tid, tuser)
        gid, gname = _extract_group_target(ev)
        if gid and gname:
            group_target_cache.setdefault(gid, gname)

    new_lines_by_month: Dict[str, List[Tuple[int, str]]] = {}
    max_seen_ms = last_event_ms

    def _add_line(ts_ms, iso_ts, line):
        nonlocal max_seen_ms
        if ts_ms <= last_event_ms:
            return
        month = _month_key(iso_ts)
        new_lines_by_month.setdefault(month, []).append((ts_ms, line))
        max_seen_ms = max(max_seen_ms, ts_ms)

    for ev in login_events:
        formatted = _format_login_logout_line(
            ev, lambda uid: _kc_resolve_username_by_id(uid, user_cache))
        if formatted:
            _add_line(*formatted)

    for ev in admin_events:
        formatted = _format_admin_event_line(
            ev,
            lambda uid: _kc_resolve_username_by_id(uid, user_cache),
            user_target_cache, group_target_cache,
            lambda gid: _kc_resolve_groupname_by_id(gid, group_target_cache),
        )
        if formatted:
            _add_line(*formatted)

    total = sum(len(v) for v in new_lines_by_month.values())

    for ev in admin_events:
        if (ev.get("resourceType") or "").upper() == "USER" and (ev.get("operationType") or "").upper() == "DELETE":
            tid, _ = _extract_user_target(ev)
            if tid:
                user_target_cache.pop(tid, None)
        if (ev.get("resourceType") or "").upper() == "GROUP" and (ev.get("operationType") or "").upper() == "DELETE":
            gid, _ = _extract_group_target(ev)
            if gid:
                group_target_cache.pop(gid, None)

    updated_user_map = {k: v for k, v in user_target_cache.items() if v}
    updated_group_map = {k: v for k, v in group_target_cache.items() if v}
    logger.info("Fetched %d login events, %d admin events", len(login_events), len(admin_events))
    return total, max_seen_ms, new_lines_by_month, updated_user_map, updated_group_map
