#!/bin/sh
# EDA User Audit SFTP sidecar entrypoint.
#
# Self-provisions the credential Secret (password + SSH host keys) via the
# Kubernetes API on first boot, and reuses it on every later boot so the SSH
# host identity and the password stay stable across pod restarts. The pod's
# ServiceAccount (eda-useraudit, wildcard ClusterRole) authorizes the calls.
#
# Authentication is PASSWORD-ONLY (user "audit"). The password is stored in
# the useraudit-sftp Secret and retrievable by the operator with kubectl.
#
# Secret keys:
#   password              plaintext password for user "audit"
#   ssh_host_ed25519_key  persistent host private key
#   ssh_host_rsa_key      persistent host private key (legacy-client compat)
set -eu

NS="${POD_NAMESPACE:-eda-system}"
SECRET_NAME="useraudit-sftp"
SA_DIR=/var/run/secrets/kubernetes.io/serviceaccount
API="https://kubernetes.default.svc"
SECRET_URL="$API/api/v1/namespaces/$NS/secrets/$SECRET_NAME"
KEY_DIR=/etc/ssh/keys
JAIL=/srv/sftp
TMP=/tmp/secret.json

log() { echo "[sftp-entrypoint] $*"; }

kapi() {
    curl -sS --connect-timeout 5 --max-time 20 \
        --cacert "$SA_DIR/ca.crt" \
        -H "Authorization: Bearer $(cat "$SA_DIR/token")" \
        "$@"
}

# ---- create the jail's device nodes -------------------------------------------
# sftp-server runs AFTER chroot into $JAIL; it opens /dev/null on startup and
# dies ("Couldn't open /dev/null") without it, never sending the SFTP VERSION
# reply (the client just hangs). The rest of the jail (shell, sftp-server, libs,
# passwd) is baked into the image; only device nodes must be created at runtime
# (they need CAP_MKNOD, which the container has).
mkdir -p "$JAIL/dev"
for spec in null:3 zero:5 urandom:9; do
    name="${spec%:*}"; minor="${spec#*:}"
    if [ ! -e "$JAIL/dev/$name" ]; then
        mknod -m 666 "$JAIL/dev/$name" c 1 "$minor" \
            || log "WARNING: mknod /dev/$name failed (need CAP_MKNOD) — SFTP may not start"
    fi
done

# ---- fetch existing secret (404 => first boot) --------------------------------
http_code=$(kapi -o "$TMP" -w '%{http_code}' "$SECRET_URL") || http_code=000
log "secret GET -> HTTP $http_code"

field() {  # field <key> -> decoded value on stdout (empty if absent)
    [ "$http_code" = "200" ] || return 0
    jq -r --arg k "$1" '.data[$k] // empty' "$TMP" | base64 -d 2>/dev/null || true
}

password=$(field password)
ed_key=$(field ssh_host_ed25519_key)
rsa_key=$(field ssh_host_rsa_key)

# ---- generate whatever is missing ---------------------------------------------
changed=0
umask 077

if [ -z "$password" ]; then
    password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)
    changed=1
    log "generated new password"
fi

if [ -n "$ed_key" ]; then
    printf '%s\n' "$ed_key" > "$KEY_DIR/ssh_host_ed25519_key"
else
    ssh-keygen -q -t ed25519 -N '' -f "$KEY_DIR/ssh_host_ed25519_key"
    ed_key=$(cat "$KEY_DIR/ssh_host_ed25519_key")
    changed=1
    log "generated new ed25519 host key"
fi

if [ -n "$rsa_key" ]; then
    printf '%s\n' "$rsa_key" > "$KEY_DIR/ssh_host_rsa_key"
else
    ssh-keygen -q -t rsa -b 3072 -N '' -f "$KEY_DIR/ssh_host_rsa_key"
    rsa_key=$(cat "$KEY_DIR/ssh_host_rsa_key")
    changed=1
    log "generated new rsa host key"
fi

# ---- push merged secret back if anything was generated ------------------------
if [ "$changed" = "1" ]; then
    body=$(jq -n \
        --arg ns "$NS" --arg name "$SECRET_NAME" \
        --arg pw "$password" --arg ed "$ed_key" --arg rsa "$rsa_key" \
        '{apiVersion: "v1", kind: "Secret",
          metadata: {name: $name, namespace: $ns,
                     labels: {"eda.nokia.com/app": "eda-useraudit"}},
          type: "Opaque",
          stringData: {password: $pw, ssh_host_ed25519_key: $ed,
                       ssh_host_rsa_key: $rsa}}')
    if [ "$http_code" = "200" ]; then
        rc=$(printf '%s' "$body" | kapi -o /dev/null -w '%{http_code}' \
             -X PUT -H 'Content-Type: application/json' -d @- "$SECRET_URL") || rc=000
    else
        rc=$(printf '%s' "$body" | kapi -o /dev/null -w '%{http_code}' \
             -X POST -H 'Content-Type: application/json' -d @- \
             "$API/api/v1/namespaces/$NS/secrets") || rc=000
    fi
    log "secret write -> HTTP $rc"
    case "$rc" in
        2*) : ;;
        *)  log "WARNING: failed to persist secret (HTTP $rc); credentials valid for this pod lifetime only" ;;
    esac
fi

# ---- set the account password -------------------------------------------------
printf 'audit:%s\n' "$password" | chpasswd -c SHA512
unset password
rm -f "$TMP"

# Bound the open-file limit before starting sshd. Talos/containerd hand
# containers a huge RLIMIT_NOFILE (1048576 vs Docker's 1024). For every session,
# sshd closes file descriptors up to this limit; when close_range(2) is blocked
# by the container seccomp profile it falls back to a per-fd close loop, which at
# ~1M iterations spins the session child (state R) before it ever execs the SFTP
# server — the connection authenticates, the subsystem is accepted, then hangs
# forever with no VERSION reply. Capping the limit makes the loop trivial.
# Observed on Talos; Docker's default 1024 masked it.
ulimit -n 1024 2>/dev/null || true

log "starting sshd (user: audit, password-only, chroot: $JAIL, read-only via external sftp-server)"
exec /usr/sbin/sshd -D -e
