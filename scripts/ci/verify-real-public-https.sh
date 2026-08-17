#!/usr/bin/env bash

set -euo pipefail

readonly repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ "${1:-}" == '--inner' && "${EGRESS_REAL_HTTPS_INNER:-}" == '1' ]]; then
  mount --bind "${EGRESS_REAL_HTTPS_RESOLV_CONF}" /etc/resolv.conf
  ip link set lo up
  ip address add 93.184.216.34/32 dev lo
  ip address add 93.184.216.35/32 dev lo
  cd -- "${repository_root}"
  cargo test --locked --package egress-broker --test real_public_https \
    real_system_dns_tls_sni_address_pin_and_rebinding_are_enforced -- --ignored --exact
  exit 0
fi

readonly fixture_dir="$(mktemp -d)"
readonly dns_hosts_path="${fixture_dir}/dns-hosts"
readonly resolv_conf_path="${fixture_dir}/resolv.conf"
readonly ca_key="${fixture_dir}/ca.key"
readonly ca_cert="${fixture_dir}/ca.pem"
readonly server_key="${fixture_dir}/server.key"
readonly server_request="${fixture_dir}/server.csr"
readonly server_cert="${fixture_dir}/server.pem"

cleanup() {
  rm -rf -- "${fixture_dir}"
}
trap cleanup EXIT

for command_name in cargo dnsmasq ip kill mount openssl unshare; do
  if ! command -v -- "${command_name}" >/dev/null 2>&1; then
    printf 'required real HTTPS prerequisite is unavailable: %s\n' "${command_name}" >&2
    exit 2
  fi
done
if [[ "$(id -u)" -ne 0 ]]; then
  printf 'real HTTPS verification requires root for isolated network and mount namespaces\n' >&2
  exit 2
fi

printf '93.184.216.35 origin.egress.test\n' > "${dns_hosts_path}"
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n' > "${resolv_conf_path}"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=Egress Broker Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "${ca_key}" -out "${ca_cert}" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes \
  -subj '/CN=public.egress.test' \
  -addext 'subjectAltName=DNS:public.egress.test' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "${server_key}" -out "${server_request}" >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 \
  -in "${server_request}" -CA "${ca_cert}" -CAkey "${ca_key}" -CAcreateserial \
  -copy_extensions copyall -out "${server_cert}" >/dev/null 2>&1

export EGRESS_REAL_HTTPS_INNER=1
export EGRESS_REAL_HTTPS_REQUIRED=1
export EGRESS_REAL_HTTPS_DIR="${fixture_dir}"
export EGRESS_REAL_HTTPS_DNS_HOSTS="${dns_hosts_path}"
export EGRESS_REAL_HTTPS_RESOLV_CONF="${resolv_conf_path}"
export EGRESS_REAL_HTTPS_CERT="${server_cert}"
export EGRESS_REAL_HTTPS_KEY="${server_key}"
export SSL_CERT_FILE="${ca_cert}"

unshare --mount --net --fork -- "${BASH_SOURCE[0]}" --inner

printf 'real public HTTPS verification: DNS, TLS/SNI, address pinning, and rebinding passed\n'
