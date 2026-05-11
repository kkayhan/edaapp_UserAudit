"""
EDA User Audit Controller - main entry point.
Poll loop, cleanup thread, signal handling, CRD status updates.
"""

import json
import logging
import os
import signal
import shutil
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

VERSION = "v0.7.0"
DATA_DIR = "/data/logs"
NAMESPACE = os.environ.get("POD_NAMESPACE", "eda-system")
CRD_GROUP = "useraudit.eda.edacommunity.com"
CRD_VERSION = "v1alpha1"
CRD_PLURAL = "userauditconfigs"
CRD_NAME = "default"
CM_NAME = "useraudit-state"

# Defaults
DEFAULT_POLL_INTERVAL = 300
DEFAULT_RETENTION = 0

logger = logging.getLogger("main")

# Shared cleanup health (protected by lock)
_cleanup_lock = threading.Lock()
_cleanup_health = [None]  # None, "degraded", or "error"
_cleanup_message = [""]

shutdown_event = threading.Event()


def _setup_logging():
    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)-5s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    fmt.converter = time.gmtime
    handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(handler)


def _signal_handler(signum, frame):
    logger.info("Received signal %d, initiating shutdown", signum)
    shutdown_event.set()


# ----------------------------- CRD config reading -----------------------------------

def _read_config():
    """Read UserAuditConfig CRD; returns (poll_interval, retention_months)."""
    import k8s
    try:
        cr = k8s.read_cr(CRD_GROUP, CRD_VERSION, CRD_PLURAL, CRD_NAME)
        if cr:
            spec = cr.get("spec", {})
            poll = spec.get("pollIntervalSeconds", DEFAULT_POLL_INTERVAL)
            retention = spec.get("retentionMonths", DEFAULT_RETENTION)
            return max(60, min(3600, poll)), max(0, retention)
    except Exception as e:
        logger.warning("Failed to read UserAuditConfig: %s", e)
    return DEFAULT_POLL_INTERVAL, DEFAULT_RETENTION


def _ensure_default_cr():
    """Create default UserAuditConfig CR if none exists."""
    import k8s
    cr = k8s.read_cr(CRD_GROUP, CRD_VERSION, CRD_PLURAL, CRD_NAME)
    if cr:
        return
    body = {
        "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
        "kind": "UserAuditConfig",
        "metadata": {"name": CRD_NAME},
        "spec": {},
    }
    try:
        k8s.create_cr(CRD_GROUP, CRD_VERSION, CRD_PLURAL, body)
        logger.info("Created default UserAuditConfig CR")
    except Exception as e:
        logger.warning("Failed to create default UserAuditConfig: %s", e)


# ----------------------------- State (ConfigMap) ------------------------------------

def _read_state():
    """Read watermarks from ConfigMap. Returns (state_dict, resource_version)."""
    import k8s
    cm = k8s.read_configmap(CM_NAME, NAMESPACE)
    if not cm:
        return None, None
    data = cm.get("data", {})
    rv = cm.get("metadata", {}).get("resourceVersion", "")
    state = {
        "lastTransactionID": int(data.get("lastTransactionID", "0") or "0"),
        "lastCommitTimestamp": data.get("lastCommitTimestamp", ""),
        "lastUserEventMs": int(data.get("lastUserEventMs", "0") or "0"),
        "users": json.loads(data.get("users", "{}")),
        "groups": json.loads(data.get("groups", "{}")),
        "lastCleanupTime": data.get("lastCleanupTime", ""),
    }
    return state, rv


def _write_state(state, resource_version=None):
    """Write watermarks to ConfigMap (create or update)."""
    import k8s
    data = {
        "lastTransactionID": str(state.get("lastTransactionID", 0)),
        "lastCommitTimestamp": state.get("lastCommitTimestamp", ""),
        "lastUserEventMs": str(state.get("lastUserEventMs", 0)),
        "users": json.dumps(state.get("users", {})),
        "groups": json.dumps(state.get("groups", {})),
        "lastCleanupTime": state.get("lastCleanupTime", ""),
    }
    # Check size warning
    total = sum(len(v) for v in data.values())
    if total > 800_000:
        logger.warning("ConfigMap size at %dKB — approaching 1MB limit", total // 1024)

    if resource_version:
        k8s.update_configmap(CM_NAME, NAMESPACE, data, resource_version)
    else:
        k8s.create_configmap(CM_NAME, NAMESPACE, data)


# ----------------------------- CRD status updates -----------------------------------

def _update_crd_status(health, message, last_poll_time, last_tx_id, last_event_ms,
                       txns_processed, kc_events_processed, subsystems):
    """Update UserAuditConfig CRD status subresource."""
    import k8s
    cr = k8s.read_cr(CRD_GROUP, CRD_VERSION, CRD_PLURAL, CRD_NAME)
    if not cr:
        return

    # Collect log file info
    log_files = []
    try:
        for name in sorted(os.listdir(DATA_DIR)):
            if name.endswith(".log"):
                full = os.path.join(DATA_DIR, name)
                if os.path.isfile(full):
                    log_files.append({"name": name, "sizeBytes": os.path.getsize(full)})
    except Exception:
        pass

    cr["status"] = {
        "health": health,
        "message": message,
        "lastPollTime": last_poll_time,
        "lastTransactionId": last_tx_id or 0,
        "lastUserEventMs": last_event_ms or 0,
        "transactionsProcessed": txns_processed,
        "kcEventsProcessed": kc_events_processed,
        "logFiles": log_files,
        "subsystems": subsystems,
        "version": VERSION,
    }

    try:
        k8s.update_cr_status(CRD_GROUP, CRD_VERSION, CRD_PLURAL, CRD_NAME, cr)
    except Exception as e:
        logger.warning("Failed to update CRD status: %s", e)


# ----------------------------- Cleanup thread ---------------------------------------

def _cleanup_run(retention_months):
    """Run cleanup: time-based retention then space-based."""
    now = datetime.now(timezone.utc)
    current_month = now.strftime("%Y-%m")
    deleted = 0

    # Time-based retention
    if retention_months > 0:
        for name in sorted(os.listdir(DATA_DIR)):
            if not name.startswith("EDA-user-events-") or not name.endswith(".log"):
                continue
            file_month = name.replace("EDA-user-events-", "").replace(".log", "")
            if file_month == current_month:
                continue
            try:
                file_year, file_mo = int(file_month[:4]), int(file_month[5:7])
                now_year, now_mo = now.year, now.month
                age_months = (now_year - file_year) * 12 + (now_mo - file_mo)
                if age_months > retention_months:
                    full = os.path.join(DATA_DIR, name)
                    size = os.path.getsize(full)
                    os.remove(full)
                    deleted += 1
                    logging.getLogger("cleanup").info("Deleted %s (%dKB, age: %d months)", name, size // 1024, age_months)
            except Exception as e:
                logging.getLogger("cleanup").warning("Failed to parse/delete %s: %s", name, e)

    # Space-based cleanup (>90% threshold)
    try:
        usage = shutil.disk_usage(DATA_DIR)
        pct = (usage.used / usage.total) * 100 if usage.total > 0 else 0
        if pct > 90:
            log_files = sorted(
                [f for f in os.listdir(DATA_DIR) if f.startswith("EDA-user-events-") and f.endswith(".log")
                 and f.replace("EDA-user-events-", "").replace(".log", "") != current_month]
            )
            for name in log_files:
                if pct <= 90:
                    break
                full = os.path.join(DATA_DIR, name)
                size = os.path.getsize(full)
                os.remove(full)
                deleted += 1
                logging.getLogger("cleanup").info("Space cleanup: deleted %s (%dKB)", name, size // 1024)
                usage = shutil.disk_usage(DATA_DIR)
                pct = (usage.used / usage.total) * 100 if usage.total > 0 else 0

            if pct > 90:
                with _cleanup_lock:
                    _cleanup_health[0] = "degraded"
                    _cleanup_message[0] = "Log storage above 90% — only current month's log remains, cannot free more space"
                logging.getLogger("cleanup").warning("Disk usage still above 90%% after cleanup")
            else:
                with _cleanup_lock:
                    _cleanup_health[0] = None
                    _cleanup_message[0] = ""
        else:
            with _cleanup_lock:
                _cleanup_health[0] = None
                _cleanup_message[0] = ""
    except Exception as e:
        logging.getLogger("cleanup").warning("Space check failed: %s", e)

    usage = shutil.disk_usage(DATA_DIR)
    pct = (usage.used / usage.total) * 100 if usage.total > 0 else 0
    logging.getLogger("cleanup").info("Disk usage: %.0f%% (cleanup complete, %d files deleted)", pct, deleted)
    return deleted


def _cleanup_thread(get_retention):
    """Background cleanup thread: startup check + daily 3 AM."""
    cleanup_logger = logging.getLogger("cleanup")

    # Read lastCleanupTime from state
    state, _ = _read_state()
    last_cleanup_str = (state or {}).get("lastCleanupTime", "")
    now = datetime.now(timezone.utc)
    run_now = True

    if last_cleanup_str:
        try:
            from keycloak_events import _parse_iso_datetime
            last_dt = _parse_iso_datetime(last_cleanup_str)
            if last_dt and (now - last_dt).total_seconds() < 72000:  # 20 hours
                run_now = False
        except Exception:
            pass

    if run_now:
        cleanup_logger.info("Running startup cleanup")
        retention = get_retention()
        _cleanup_run(retention)
        _update_cleanup_time()

    # Schedule daily at 3 AM
    while not shutdown_event.is_set():
        now = datetime.now()
        next_3am = now.replace(hour=3, minute=0, second=0, microsecond=0)
        if now >= next_3am:
            next_3am = next_3am.replace(day=next_3am.day + 1)
        wait_secs = (next_3am - now).total_seconds()
        if shutdown_event.wait(timeout=wait_secs):
            break  # shutdown
        cleanup_logger.info("Daily cleanup started (retention: %d months)", get_retention())
        _cleanup_run(get_retention())
        _update_cleanup_time()


def _update_cleanup_time():
    """Update lastCleanupTime in ConfigMap."""
    try:
        state, rv = _read_state()
        if state and rv:
            state["lastCleanupTime"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            _write_state(state, rv)
    except Exception as e:
        logging.getLogger("cleanup").warning("Failed to update lastCleanupTime: %s", e)


# ----------------------------- Main poll loop ---------------------------------------

def main():
    _setup_logging()
    logger.info("Controller started (version %s)", VERSION)

    # Ensure data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Import after logging is set up
    import auth
    import keycloak_events as kc
    import transaction as txn
    import fileserver

    # Start file server
    fileserver.start_file_server(8080)

    # Write initial healthz
    fileserver.write_healthz("starting", None)

    # Wait briefly for TLS certs to be injected
    time.sleep(2)

    # Initialize SSL context
    auth.get_ssl_context()

    # Ensure default CR exists
    _ensure_default_cr()

    # Retention getter for cleanup thread
    current_retention = [DEFAULT_RETENTION]

    def _get_retention():
        return current_retention[0]

    # Start cleanup thread
    cleanup_t = threading.Thread(target=_cleanup_thread, args=(_get_retention,), daemon=True, name="cleanup")
    cleanup_t.start()

    # Counters (since controller started)
    total_txns = 0
    total_kc_events = 0
    last_successful_poll = None

    while not shutdown_event.is_set():
        cycle_start = time.time()
        poll_interval, retention = _read_config()
        current_retention[0] = retention
        logger.info("Config loaded: pollInterval=%ds, retention=%d months", poll_interval, retention)

        # Read state
        state, rv = _read_state()
        first_run = state is None

        if first_run:
            # First run: discover watermark, set KC to now
            logger.info("First run detected — discovering current watermark")
            try:
                auth.get_eda_api_token()
                current_tx_id = txn.discover_current_watermark()
            except Exception as e:
                logger.error("Failed to initialize on first run: %s", e)
                fileserver.write_healthz("error", None)
                shutdown_event.wait(timeout=poll_interval)
                continue

            now_ms = int(time.time() * 1000)
            state = {
                "lastTransactionID": current_tx_id,
                "lastCommitTimestamp": "",
                "lastUserEventMs": now_ms,
                "users": {},
                "groups": {},
                "lastCleanupTime": "",
            }
            try:
                _write_state(state)
                rv = None  # will re-read on next cycle
            except Exception as e:
                logger.error("Failed to write initial state: %s", e)
            logger.info("First run: starting from transaction %d, KC watermark set to now", current_tx_id)
            fileserver.write_healthz("ok", datetime.now(timezone.utc).isoformat(timespec="seconds"))
            _update_crd_status("ok", "Initialized — first poll cycle starting",
                              datetime.now(timezone.utc).isoformat(timespec="seconds"),
                              current_tx_id, now_ms, total_txns, total_kc_events,
                              {"edaApi": "ok", "keycloakEvents": "ok"})
            shutdown_event.wait(timeout=min(10, poll_interval))  # Short wait before first real poll
            continue

        last_tx_id = state.get("lastTransactionID", 0)
        last_event_ms = state.get("lastUserEventMs", 0)
        user_map = state.get("users", {})
        group_map = state.get("groups", {})

        eda_health = "ok"
        kc_health = "ok"
        poll_ok = True

        # Ensure KC events enabled
        try:
            kc.ensure_events_enabled()
        except Exception as e:
            logger.warning("KC event enablement failed: %s", e)

        # Poll transactions
        txn_lines_by_month = {}
        last_processed = None
        last_tx_iso = None
        tx_count = 0
        try:
            txn_lines_by_month, last_processed, last_tx_iso, tx_count = txn.poll_transactions(last_tx_id)
            total_txns += tx_count
        except Exception as e:
            logger.error("Transaction polling failed: %s\n%s", e, traceback.format_exc())
            eda_health = "error"
            poll_ok = False

        # Poll KC events
        kc_count = 0
        kc_lines_by_month = {}
        new_event_ms = last_event_ms
        try:
            kc_count, new_event_ms, kc_lines_by_month, user_map, group_map = kc.collect_keycloak_user_logs(
                last_event_ms, user_map, group_map
            )
            total_kc_events += kc_count
        except Exception as e:
            logger.warning("KC event collection failed: %s", e)
            kc_health = "error"

        # Write log lines
        months = sorted(set(list(txn_lines_by_month.keys()) + list(kc_lines_by_month.keys())))
        total_lines = 0
        for month in months:
            combined = []
            combined.extend(txn_lines_by_month.get(month, []))
            combined.extend(kc_lines_by_month.get(month, []))
            if not combined:
                continue
            combined.sort(key=lambda x: (x[0], x[1]))
            out = Path(DATA_DIR) / f"EDA-user-events-{month}.log"
            with out.open("a", encoding="utf-8") as fh:
                for _, line in combined:
                    fh.write(line + "\n")
                    total_lines += 1

        # Update state
        if last_processed is not None:
            state["lastTransactionID"] = last_processed
            state["lastCommitTimestamp"] = last_tx_iso or ""
        if new_event_ms > last_event_ms:
            state["lastUserEventMs"] = new_event_ms
        state["users"] = user_map
        state["groups"] = group_map

        try:
            # Re-read to get fresh resource version
            _, fresh_rv = _read_state()
            if fresh_rv:
                _write_state(state, fresh_rv)
            else:
                _write_state(state)
        except Exception as e:
            logger.error("Failed to write state: %s", e)

        # Determine health
        now_str = datetime.now(timezone.utc).isoformat(timespec="seconds")
        subsystems = {"edaApi": eda_health, "keycloakEvents": kc_health}

        # Check cleanup health
        with _cleanup_lock:
            c_health = _cleanup_health[0]
            c_msg = _cleanup_message[0]
            _cleanup_health[0] = None
            _cleanup_message[0] = ""

        if poll_ok:
            last_successful_poll = time.time()

        # Stale poll detection
        overall_health = "ok"
        overall_message = "All systems operational"
        if eda_health != "ok" and kc_health != "ok":
            overall_health = "error"
            overall_message = "Both EDA API and Keycloak unreachable"
        elif eda_health != "ok":
            overall_health = "degraded"
            overall_message = "EDA API unavailable"
        elif kc_health != "ok":
            overall_health = "degraded"
            overall_message = "Keycloak events unavailable"

        if last_successful_poll and (time.time() - last_successful_poll) > 6 * poll_interval:
            overall_health = "error"
            overall_message = f"No successful poll in {int((time.time() - last_successful_poll) / 60)} minutes"
        elif last_successful_poll and (time.time() - last_successful_poll) > 3 * poll_interval:
            overall_health = "degraded"
            overall_message = f"No successful poll in {int((time.time() - last_successful_poll) / 60)} minutes"

        if c_health and (c_health == "degraded" or c_health == "error"):
            if overall_health == "ok":
                overall_health = c_health
                overall_message = c_msg

        # Update CRD status
        _update_crd_status(
            overall_health, overall_message, now_str,
            state.get("lastTransactionID", 0),
            state.get("lastUserEventMs", 0),
            total_txns, total_kc_events, subsystems,
        )

        # Write healthz
        fileserver.write_healthz(overall_health, now_str)

        cycle_ms = int((time.time() - cycle_start) * 1000)
        poll_logger = logging.getLogger("poll")
        poll_logger.info("Poll cycle completed: %d transactions, %d KC events, %d lines written (%dms)",
                        tx_count, kc_count, total_lines, cycle_ms)
        logger.info("Next poll in %ds", poll_interval)

        shutdown_event.wait(timeout=poll_interval)

    logger.info("Controller shutting down")


if __name__ == "__main__":
    main()
