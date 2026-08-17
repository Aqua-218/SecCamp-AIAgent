# host-sessiond deployment boundary

`service/host-sessiond.service` runs the repository's one-session owner as a dedicated
`host-sessiond` account. It is intentionally not a multi-session API or a privileged control
plane. Install the binary, this unit, and a copy of `host-sessiond.env.example` as
`/etc/host-sessiond/host-sessiond.env`, then replace every placeholder digest with the digest of
the exact artifact on disk.

Build and install the exact binary from the reviewed source revision (the package is not a
generic `cargo install` target):

```sh
cargo build --release --locked -p session-orchestrator --bin host-sessiond
install -o root -g root -m 0755 target/release/host-sessiond /usr/local/bin/host-sessiond
```

Before enabling the unit, provision the account and device access explicitly:

```sh
useradd --system --home-dir /var/lib/host-sessiond --shell /usr/sbin/nologin host-sessiond
usermod --append --groups kvm host-sessiond
# The device-mapper control node is normally root-only.  Install a narrowly scoped udev rule
# (and reload udev) so this service account can open only the control node and its own mapper
# prefix; do not add the account to the broad `disk` group.
cat >/etc/udev/rules.d/70-host-sessiond-device-mapper.rules <<'EOF'
KERNEL=="device-mapper", GROUP="host-sessiond", MODE="0660"
KERNEL=="dm-*", ENV{DM_NAME}=="host-sessiond-rootfs-*", GROUP="host-sessiond", MODE="0660"
EOF
udevadm control --reload-rules
udevadm trigger --subsystem-match=misc --action=add
install -d -o host-sessiond -g host-sessiond -m 0750 \
  /var/lib/host-sessiond /var/lib/host-sessiond/jailer \
  /var/lib/host-sessiond/workspace-source
install -d -o host-sessiond -g host-sessiond -m 0750 /etc/host-sessiond
install -o root -g host-sessiond -m 0640 deploy/host-sessiond.env.example \
  /etc/host-sessiond/host-sessiond.env
install -o root -g root -m 0644 service/host-sessiond.service \
  /etc/systemd/system/host-sessiond.service
systemctl daemon-reload
systemctl enable --now host-sessiond.service
```

The example uses `--egress-authority none` and contains no GitHub token. Public HTTPS or GitHub
must be enabled by an explicit unit/configuration change. A GitHub token, when that profile is
selected, is host-only input (`EGRESS_GITHUB_TOKEN`) and must come from a runtime secret manager;
it must not be committed to the environment file.

`publish-branch` additionally requires a host-owned plan manifest. Keep it outside the environment
file, for example in `/var/lib/host-sessiond/github-publish-plans.tsv`, with an owner-only parent
directory and file mode `0600` owned by `host-sessiond`:

```sh
install -d -o host-sessiond -g host-sessiond -m 0700 /var/lib/host-sessiond/publish-plans
install -o host-sessiond -g host-sessiond -m 0600 /path/from-the-deployment-controller/plans.tsv \
  /var/lib/host-sessiond/publish-plans/github-publish-plans.tsv
```

The strict, LF-delimited manifest has one canonical line per request and no comments:

```text
host-publish-plan-v1<TAB>request-id-hex<TAB>installation<TAB>repository<TAB>publish-branch<TAB>base<TAB>head<TAB>new-object-id<TAB>expected-old-object-id
```

Object IDs and request IDs are lowercase hexadecimal; the operation is exactly
`publish-branch`. The request ID is caller-selected and must be the same ID passed to
`GuestBrokerClient::request_with_id`; it is not generated or inferred by the daemon. Every line
must match the configured installation, repository, and branch patterns. Add the path and the
canonical GitHub flags to the unit's `ExecStart` only when selecting the GitHub profile. A
`create-pull-request`-only profile does not need a plan manifest. Never put a token or other
credential in this file.

`HOST_SESSIOND_AUTHORITY_AUDIT_MODE=auto` creates the audit journal exclusively on the first
start and reopens the same owner-validated journal on later starts. Use `create` only when
provisioning a new, absent journal and `open` when an existing journal is intentionally being
recovered; an existing journal is never overwritten.

The process needs `/dev/kvm`, `/dev/vhost-vsock`, and narrowly scoped device-mapper access, plus
permission to create the configured cgroup and mount/pid namespaces. The unit grants only that
host-side envelope and keeps `PrivateNetwork=no` because public HTTPS/GitHub egress is performed
by the host broker. `NoNewPrivileges=yes` is compatible with the unit because the Jailer and helper
processes receive their explicit ambient capability set; the service account's configured jailer
UID/GID must match the account. Do not use root for those values.

Readiness and lifecycle state are JSON lines on the journal and in
`/run/host-sessiond/status.json`. The record contains only opaque session/workspace/subject/
capability IDs and fixed event names; it never contains credentials, authority bodies, paths, or
backend error text. `SIGTERM`, `SIGINT`, and the stop file trigger dependency-ordered cleanup for
`HOST_SESSIOND_SHUTDOWN_TIMEOUT_MILLIS`; a timeout exits non-zero so the durable recovery path is
used on the next start.
