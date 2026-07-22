FROM alpine:3.21
LABEL org.opencontainers.image.source="https://github.com/kkayhan/eda-catalog"
LABEL org.opencontainers.image.description="EDA User Audit SFTP sidecar (read-only audit log access)"
LABEL org.opencontainers.image.license="MIT"

# openssh-server:        sshd + ssh-keygen
# openssh-sftp-server:   the standalone /usr/lib/ssh/sftp-server binary. We use
#                        this instead of sshd's built-in `internal-sftp` because
#                        internal-sftp (which runs in-process, without re-exec)
#                        fails to start inside a chroot on some container
#                        runtimes (observed on Talos: it hangs after the SFTP
#                        subsystem is accepted, emitting no VERSION). The
#                        externally-exec'd sftp-server works reliably in the same
#                        jail, at the cost of needing a shell + the binary inside
#                        the ChrootDirectory (built below).
# shadow:                chpasswd -c SHA512 (busybox chpasswd lacks -c)
# curl + jq:             Kubernetes API access from entrypoint (secret provisioning)
RUN apk add --no-cache openssh-server openssh-sftp-server shadow curl jq \
    && adduser -D -H -h /logs -s /bin/sh -u 1000 audit \
    && mkdir -p /etc/ssh/keys \
    && chmod 700 /etc/ssh/keys

# Build the chroot jail. sshd execs the forced SFTP command via the user's login
# shell AFTER chroot, so the jail must be a minimal self-contained root: a shell
# (busybox), the sftp-server binary, the musl loader they both link against, and
# a minimal passwd/group so the account resolves. /dev nodes are created at
# runtime by the entrypoint (needs CAP_MKNOD). /srv/sftp itself must be
# root-owned and not group/other-writable for sshd's chroot safety check.
RUN set -eux; \
    JAIL=/srv/sftp; \
    mkdir -p "$JAIL/bin" "$JAIL/usr/lib/ssh" "$JAIL/lib" "$JAIL/etc" "$JAIL/dev" "$JAIL/logs"; \
    cp /bin/busybox "$JAIL/bin/"; \
    ln -s busybox "$JAIL/bin/sh"; \
    cp /usr/lib/ssh/sftp-server "$JAIL/usr/lib/ssh/"; \
    cp /lib/ld-musl-x86_64.so.1 "$JAIL/lib/"; \
    printf 'audit:x:1000:1000::/logs:/bin/sh\n' > "$JAIL/etc/passwd"; \
    printf 'audit:x:1000:\n' > "$JAIL/etc/group"; \
    chown root:root "$JAIL"; \
    chmod 755 "$JAIL"

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
