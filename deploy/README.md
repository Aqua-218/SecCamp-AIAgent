# host-sessiond deployment boundaries

The production multi-session composition has three privilege levels:

1. callers in the `host-control` group run `host-control`; the kernel-observed Unix peer UID is
   the caller principal;
2. unprivileged `host-controld` authenticates the fixed-width start/stop request, enforces quota
   and durable identity non-reuse, and asks systemd for one fixed template instance;
3. each `host-sessiond@ID.service` owns exactly one session and one microVM. Only these workers
   receive the bounded KVM, device-mapper, cgroup, and namespace capability envelope.

The shared HMAC key never crosses into a guest. A caller cannot send a program, unit name, path,
systemd property, guest credential, or arbitrary host command through the control socket. The
polkit rule accepts only start/stop of a 32-lowercase-hex worker instance and start of its matching
recovery instance. A failed worker remains a visible systemd tombstone, but the controller releases
ownership only after its exact stop transaction and recovery instance succeed.

## Production multi-session installation

Build and install all three binaries only from an externally authenticated, reviewed full commit
ID and an externally authenticated SHA-256 manifest. Do not take either expected value from the
checkout being verified. The package is not a generic `cargo install` target, and an uncommitted or
untracked source file is an installation failure. The reviewed manifest must contain exactly these
three relative names, one per line in standard `sha256sum` format: `host-sessiond`,
`host-controld`, and `host-control`.

The root-owned staging directory closes the build-to-install race: the mutable Cargo output is
copied once, the copy is checked against the externally authenticated manifest, and installation
and post-install verification use only that checked copy. A locally built binary whose digest does
not match the reviewed manifest is not deployable, even when its checkout has the reviewed commit
ID.

```bash
set -Eeuo pipefail
reviewed_revision=REPLACE_WITH_REVIEWED_FULL_COMMIT_SHA
reviewed_manifest=/secure/input/host-sessiond-binaries.sha256
reviewed_manifest_sha256=REPLACE_WITH_EXTERNALLY_AUTHENTICATED_MANIFEST_SHA256
test "$(git rev-parse HEAD)" = "${reviewed_revision}"
test -z "$(git status --porcelain=v1 --untracked-files=normal)"
test "$(sha256sum "${reviewed_manifest}" | cut -d' ' -f1)" = "${reviewed_manifest_sha256}"
test "$(wc -l <"${reviewed_manifest}")" = 3
grep -Eq '^[0-9a-f]{64}  host-sessiond$' "${reviewed_manifest}"
grep -Eq '^[0-9a-f]{64}  host-controld$' "${reviewed_manifest}"
grep -Eq '^[0-9a-f]{64}  host-control$' "${reviewed_manifest}"
cargo build --release --locked -p session-orchestrator \
  --bin host-sessiond --bin host-controld --bin host-control
install_staging="$(mktemp -d /var/tmp/host-sessiond-install.XXXXXX)"
trap 'rm -rf -- "${install_staging}"' EXIT HUP INT TERM
chown root:root "${install_staging}"
chmod 0700 "${install_staging}"
install -o root -g root -m 0500 target/release/host-sessiond "${install_staging}/host-sessiond"
install -o root -g root -m 0500 target/release/host-controld "${install_staging}/host-controld"
install -o root -g root -m 0500 target/release/host-control "${install_staging}/host-control"
install -o root -g root -m 0400 "${reviewed_manifest}" \
  "${install_staging}/host-sessiond-binaries.sha256"
(cd "${install_staging}" && sha256sum --check --strict host-sessiond-binaries.sha256)
install -o root -g root -m 0755 "${install_staging}/host-sessiond" /usr/local/bin/host-sessiond
install -o root -g root -m 0755 "${install_staging}/host-controld" /usr/local/bin/host-controld
install -o root -g root -m 0755 "${install_staging}/host-control" /usr/local/bin/host-control
while read -r expected_digest binary; do
  test "$(sha256sum "/usr/local/bin/${binary}" | cut -d' ' -f1)" = "${expected_digest}"
done <"${install_staging}/host-sessiond-binaries.sha256"
rm -rf -- "${install_staging}"
trap - EXIT HUP INT TERM
```

Provision the control group, the two service accounts, and the required device access. The
numeric values are deployment inputs, but the GID in `controld.env`, the `host-control` group GID,
the HMAC key group, and the client `--client-gid` must be exactly equal. The worker UID/GID must
also equal `HOST_SESSIOND_JAILER_UID` and `HOST_SESSIOND_JAILER_GID`.

```bash
set -Eeuo pipefail
getent group host-control >/dev/null || groupadd --system --gid 2000 host-control
getent passwd host-controld >/dev/null || useradd --system --uid 960 --gid host-control \
  --home-dir /var/lib/host-controld --shell /usr/sbin/nologin host-controld
getent group host-sessiond >/dev/null || groupadd --system --gid 961 host-sessiond
getent passwd host-sessiond >/dev/null || useradd --system --uid 961 --gid 961 \
  --home-dir /var/lib/host-sessiond --shell /usr/sbin/nologin host-sessiond
test "$(getent group host-control | cut -d: -f3)" = 2000
test "$(id -u host-controld)" = 960
test "$(id -g host-controld)" = 2000
test "$(id -u host-sessiond)" = 961
test "$(id -g host-sessiond)" = 961
usermod --append --groups kvm host-sessiond
```

Do not add `host-sessiond` to the broad `disk` group. Install the repository rule for the
device-mapper control node, this service's mapper prefix, and the loop devices that
`veritysetup` allocates when its pinned data/hash inputs are regular files. The systemd unit's
closed device policy admits only KVM/vsock, loop, and device-mapper classes; the worker remains
trusted host TCB within that envelope. Loop and device-mapper block access is class-wide because
`veritysetup` allocates dynamic minors, and every worker uses the same service identity. This
design does not claim cross-worker containment after the worker/Firecracker TCB is compromised.

```bash
set -Eeuo pipefail
install -o root -g root -m 0644 deploy/70-host-sessiond-device-mapper.rules \
  /etc/udev/rules.d/70-host-sessiond-device-mapper.rules
udevadm control --reload-rules
udevadm trigger --subsystem-match=misc --subsystem-match=block --action=add
udevadm settle
```

Provision the immutable workspace template, controller configuration, and the exact 32-byte HMAC
key. Replace every placeholder digest with the digest of the artifact on disk, including
`/usr/bin/systemctl`.

```bash
set -Eeuo pipefail
install -d -o root -g host-control -m 0750 /etc/host-controld
install -d -o root -g host-sessiond -m 0750 /etc/host-sessiond
install -d -o host-sessiond -g host-sessiond -m 0750 \
  /var/lib/host-sessiond /var/lib/host-sessiond/instances
install -d -o root -g host-sessiond -m 0550 \
  /var/lib/host-sessiond/workspace-source
install -o root -g host-control -m 0640 deploy/host-controld.env.example \
  /etc/host-controld/controld.env
install -o root -g host-sessiond -m 0640 deploy/host-sessiond-worker.env.example \
  /etc/host-sessiond/worker.env
umask 077
openssl rand -out /etc/host-controld/control.key 32
chown host-controld:host-control /etc/host-controld/control.key
chmod 0440 /etc/host-controld/control.key
test "$(stat -c %s /etc/host-controld/control.key)" = 32
```

Install the fixed service templates and the polkit rule. Template units are not enabled directly;
the authenticated controller starts and recovers their exact instances.

```bash
set -Eeuo pipefail
install -o root -g root -m 0644 service/host-sessiond@.service \
  /etc/systemd/system/host-sessiond@.service
install -o root -g root -m 0644 service/host-sessiond-recover@.service \
  /etc/systemd/system/host-sessiond-recover@.service
install -o root -g root -m 0644 service/host-controld.service \
  /etc/systemd/system/host-controld.service
install -o root -g root -m 0644 deploy/polkit-1/rules.d/50-host-controld.rules \
  /etc/polkit-1/rules.d/50-host-controld.rules
systemd-analyze verify /etc/systemd/system/host-controld.service \
  /etc/systemd/system/host-sessiond@.service \
  /etc/systemd/system/host-sessiond-recover@.service
systemctl daemon-reload
systemctl restart polkit.service
systemctl enable --now host-controld.service
```

Grant a caller group membership only after review, then start and stop by the returned opaque
session ID. Re-login before using a newly added supplementary group.

```bash
set -Eeuo pipefail
usermod --append --groups host-control CALLER
host-control --socket /run/host-controld/control.sock \
  --key-file /etc/host-controld/control.key --client-gid 2000 start
host-control --socket /run/host-controld/control.sock \
  --key-file /etc/host-controld/control.key --client-gid 2000 stop SESSION_ID
```

Controller restart reopens the owner-only journal, fences a second controller, and reconciles every
reserved or active worker through the recovery template before admitting new work. Never delete
the journal, per-instance recovery files, Broker WALs, mapper devices, jail trees, or cgroups by
hand. If reconciliation cannot prove cleanup, startup fails closed.

## Legacy single-session installation

`service/host-sessiond.service` runs one session owner as a dedicated `host-sessiond` account. It
is not a multi-session API. Install the binary, this unit, and a copy of
`host-sessiond.env.example` as `/etc/host-sessiond/host-sessiond.env`, then replace every
placeholder digest with the digest of the exact artifact on disk.

The legacy unit must reuse `/usr/local/bin/host-sessiond` installed by the authenticated revision,
manifest, root-owned staging, and post-install procedure above. Do not rebuild or reinstall a
second copy for this path; that would recreate an unauthenticated privileged installation route.

Before enabling the unit, provision the account and device access explicitly:

```bash
set -Eeuo pipefail
getent group host-sessiond >/dev/null || groupadd --system --gid 961 host-sessiond
getent passwd host-sessiond >/dev/null || useradd --system --uid 961 --gid 961 \
  --home-dir /var/lib/host-sessiond --shell /usr/sbin/nologin host-sessiond
test "$(id -u host-sessiond)" = 961
test "$(id -g host-sessiond)" = 961
usermod --append --groups kvm host-sessiond
# Device-mapper control and loop nodes are normally root/disk-only. Do not add this account to `disk`.
install -o root -g root -m 0644 deploy/70-host-sessiond-device-mapper.rules \
  /etc/udev/rules.d/70-host-sessiond-device-mapper.rules
udevadm control --reload-rules
udevadm trigger --subsystem-match=misc --subsystem-match=block --action=add
udevadm settle
install -d -o host-sessiond -g host-sessiond -m 0750 \
  /var/lib/host-sessiond /var/lib/host-sessiond/jailer
install -d -o root -g host-sessiond -m 0550 \
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
selected, is host-only input and must come from a runtime secret manager; it must not be committed
to the environment file. `RustlsGitHubProvider` first accepts `EGRESS_GITHUB_TOKEN` for non-systemd
launches and otherwise reads the bounded `github-token` systemd credential. For production, use an
encrypted credential and a unit drop-in:

```bash
set -Eeuo pipefail
systemd-creds encrypt --name=github-token /secure/input/github-token \
  /etc/credstore.encrypted/host-sessiond.github-token
systemctl edit host-sessiond.service <<'EOF'
[Service]
LoadCredentialEncrypted=github-token:/etc/credstore.encrypted/host-sessiond.github-token
EOF
```

The provider validates the credential file as a singly linked, non-symlink regular file, bounds it
to 4096 bytes, strips one line ending, and zeroizes its retained token buffer on drop.

`publish-branch` additionally requires a host-owned plan manifest. Keep it outside the environment
file, for example in `/var/lib/host-sessiond/github-publish-plans.tsv`, with an owner-only parent
directory and file mode `0600` owned by `host-sessiond`:

```bash
set -Eeuo pipefail
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

## Snapshot provisioning

`HOST_SESSIOND_SNAPSHOT_STATE` and `HOST_SESSIOND_SNAPSHOT_MEMORY` are mandatory inputs, not files
the daemon guesses or creates. Build the guest kernel and dm-verity image with the repository
scripts, boot that exact kernel/rootfs/seccomp combination without injecting a session identity,
pause the VM at the closed pre-session gate, and issue Firecracker's `Full` snapshot request. Move
the resulting state and memory files into a root-owned, non-writable artifact directory, calculate
their SHA-256 values, and set all four snapshot path/digest variables together. Then run:

```bash
set -Eeuo pipefail
sha256sum --check <<EOF
${HOST_SESSIOND_SNAPSHOT_STATE_SHA256}  ${HOST_SESSIOND_SNAPSHOT_STATE}
${HOST_SESSIOND_SNAPSHOT_MEMORY_SHA256}  ${HOST_SESSIOND_SNAPSHOT_MEMORY}
EOF
systemd-analyze verify /etc/systemd/system/host-sessiond.service
sudo -u host-sessiond test -r "${HOST_SESSIOND_SNAPSHOT_STATE}"
sudo -u host-sessiond test -r "${HOST_SESSIOND_SNAPSHOT_MEMORY}"
```

Any kernel, rootfs, verity root, Firecracker, seccomp, machine-size, boot-argument, or snapshot
change requires a new snapshot and new digests. The daemon recomputes the compatibility
fingerprint and both file digests before restore; it never falls back to an older snapshot.

The worker `HOST_SESSIOND_GUEST_CID`, `HOST_SESSIOND_GUEST_CONTROL_PORT`, and
`HOST_SESSIOND_BROKER_PORT` values must exactly match the values used while creating the snapshot;
the guest CID and PID 1 arguments are retained by the snapshot. They are intentionally shared by
all clones. Firecracker 1.16 or newer routes each clone through the worker's distinct overridden
UDS path, so equal guest CIDs and guest ports do not merge host transports. Do not derive these
snapshot-bound values from the controller session ID. The `--port` and `--broker-port` values
inside `HOST_SESSIOND_BOOT_ARGS` must also equal the corresponding worker environment values.

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

If a custom persistent stop-file path is configured, remove it only after confirming no daemon or
recovery process is live, then start the unit. The default `/run/host-sessiond/stop` is removed with
the systemd runtime directory. Never delete recovery journals, Broker WALs, mapper devices, or jail
trees manually; a non-zero shutdown leaves their exact durable recovery stage for the next start.
