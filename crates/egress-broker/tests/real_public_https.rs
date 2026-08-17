//! Real DNS and rustls integration for the public HTTPS broker boundary.
//!
//! Specification: `docs/egress-broker/network-policy.md`, "connector inputs"
//! and "exact verification scope".
//! Coverage: the production connector uses the policy-validated socket address,
//! preserves the canonical host for TLS SNI/certificate verification, and
//! re-runs the production system resolver after a redirect.
//! Prerequisites: Linux mount/network namespaces, root, `dnsmasq`, `ip`, and `openssl`.
//! The repository wrapper `scripts/ci/verify-real-public-https.sh` creates the
//! isolated network and certificate fixture before running this ignored test.

#![cfg(target_os = "linux")]

use std::{
    fmt::Write as _,
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use authority_core::http::{
    CanonicalHost, CanonicalUrlPath, HttpFetchAuthority, HttpFetchMethod, HttpFetchMethods,
    HttpFetchRequest, UrlPathPattern,
};
use egress_broker::{
    ip_policy::{IpPolicy, IpPolicyError},
    public_fetch::{
        FetchError, FetchPolicy, PublicFetcher, ResolveError, Resolver, RustlsHttpsConnector,
        SystemResolver,
    },
};

const TEST_HOST: &str = "public.egress.test";
const DNS_TARGET_HOST: &str = "origin.egress.test";
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const UNUSED_DNS_IP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 35);
const HTTPS_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(SERVER_IP), 443);

struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct DnsGuard(Child);

impl DnsGuard {
    fn reload(&self) -> io::Result<()> {
        let status = Command::new("kill")
            .args(["-HUP", &self.0.id().to_string()])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("dnsmasq rejected the reload signal"))
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Clone, Copy)]
struct PinnedResolver;

impl Resolver for PinnedResolver {
    fn resolve(&self, _host: &CanonicalHost) -> Result<Vec<IpAddr>, ResolveError> {
        Ok(vec![IpAddr::V4(SERVER_IP)])
    }
}

struct RebindingSystemResolver {
    dns_hosts_path: PathBuf,
    dns_process_id: u32,
    calls: Mutex<usize>,
}

impl Resolver for RebindingSystemResolver {
    fn resolve(&self, host: &CanonicalHost) -> Result<Vec<IpAddr>, ResolveError> {
        let addresses = SystemResolver.resolve(host)?;
        let mut calls = self.calls.lock().map_err(|_| ResolveError::Unavailable)?;
        *calls += 1;
        if *calls == 1 {
            replace_dns_target(&self.dns_hosts_path, Ipv4Addr::LOCALHOST)
                .map_err(|_| ResolveError::Unavailable)?;
            let status = Command::new("kill")
                .args(["-HUP", &self.dns_process_id.to_string()])
                .status()
                .map_err(|_| ResolveError::Unavailable)?;
            if !status.success() {
                return Err(ResolveError::Unavailable);
            }
        }
        Ok(addresses)
    }
}

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name).map_or_else(
        || panic!("{name} must be set by verify-real-public-https.sh"),
        PathBuf::from,
    )
}

fn replace_dns_target(path: &Path, address: Ipv4Addr) -> io::Result<()> {
    let current = fs::read_to_string(path)?;
    let mut next = current
        .lines()
        .filter(|line| {
            !line
                .split_ascii_whitespace()
                .any(|field| field == DNS_TARGET_HOST)
        })
        .collect::<Vec<_>>()
        .join("\n");
    if !next.is_empty() {
        next.push('\n');
    }
    writeln!(next, "{address} {DNS_TARGET_HOST}").expect("writing to a String cannot fail");
    fs::write(path, next)
}

fn start_dns_server(dns_hosts_path: &Path) -> DnsGuard {
    let child = Command::new("dnsmasq")
        .args([
            "--keep-in-foreground",
            "--user=root",
            "--no-hosts",
            "--no-resolv",
            "--bind-interfaces",
            "--listen-address=127.0.0.1",
            "--port=53",
            "--cache-size=0",
            "--local-ttl=0",
            "--cname=public.egress.test,origin.egress.test",
            "--addn-hosts",
        ])
        .arg(dns_hosts_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("dnsmasq must start in the isolated network namespace");
    let guard = DnsGuard(child);
    let host = CanonicalHost::new(TEST_HOST).expect("fixture host is canonical");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if SystemResolver.resolve(&host).is_ok() {
            return guard;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("dnsmasq did not answer the controlled CNAME query");
}

fn write_http_fixture(directory: &Path, name: &str, response: &[u8]) {
    fs::write(directory.join(name), response).expect("HTTP fixture must be writable");
}

fn start_https_server(directory: &Path) -> ServerGuard {
    let child = Command::new("openssl")
        .args([
            "s_server",
            "-quiet",
            "-accept",
            &HTTPS_ADDRESS.to_string(),
            "-cert",
        ])
        .arg(required_path("EGRESS_REAL_HTTPS_CERT"))
        .arg("-key")
        .arg(required_path("EGRESS_REAL_HTTPS_KEY"))
        .arg("-HTTP")
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("openssl s_server must start");
    let guard = ServerGuard(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&HTTPS_ADDRESS, Duration::from_millis(50)).is_ok() {
            return guard;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("openssl s_server did not listen on {HTTPS_ADDRESS}");
}

fn request(path: &str) -> HttpFetchRequest {
    HttpFetchRequest::new(
        HttpFetchMethod::Get,
        CanonicalHost::new(TEST_HOST).expect("fixture host is canonical"),
        CanonicalUrlPath::new(path).expect("fixture path is canonical"),
        4_096,
    )
}

fn authority() -> HttpFetchAuthority {
    HttpFetchAuthority::new(
        HttpFetchMethods::only(HttpFetchMethod::Get),
        CanonicalHost::new(TEST_HOST).expect("fixture host is canonical"),
        UrlPathPattern::Prefix(CanonicalUrlPath::new("/").expect("fixture path is canonical")),
        4_096,
    )
}

// Requirement: a production rustls request must connect to the already
// validated address while retaining the canonical host for SNI and certificate
// validation. A redirect must perform a fresh OS resolution and reject a
// rebound private address before opening a second connection.
// Category: integration/security/contract. Risk: critical.
#[test]
#[ignore = "requires scripts/ci/verify-real-public-https.sh"]
fn real_system_dns_tls_sni_address_pin_and_rebinding_are_enforced() {
    assert_eq!(
        std::env::var("EGRESS_REAL_HTTPS_REQUIRED").as_deref(),
        Ok("1"),
        "the ignored test must run only through its required-mode wrapper"
    );
    let fixture_dir = required_path("EGRESS_REAL_HTTPS_DIR");
    let dns_hosts_path = required_path("EGRESS_REAL_HTTPS_DNS_HOSTS");
    write_http_fixture(
        &fixture_dir,
        "payload",
        b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nreal tls payload",
    );
    write_http_fixture(
        &fixture_dir,
        "redirect",
        b"HTTP/1.1 302 Found\r\nLocation: https://public.egress.test/payload\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    replace_dns_target(&dns_hosts_path, UNUSED_DNS_IP)
        .expect("controlled DNS hosts file must be mutable");
    let dns = start_dns_server(&dns_hosts_path);
    let _server = start_https_server(&fixture_dir);

    // The OS resolver intentionally points somewhere with no listener. Success
    // therefore proves reqwest used the policy-supplied SERVER_IP instead of
    // performing an unvalidated second lookup, while the certificate proves
    // that the canonical host was retained for TLS SNI.
    assert_eq!(
        SystemResolver
            .resolve(&CanonicalHost::new(TEST_HOST).expect("fixture host"))
            .expect("system resolver must follow the controlled DNS CNAME"),
        vec![IpAddr::V4(UNUSED_DNS_IP)]
    );
    let pinned_fetcher = PublicFetcher::new(
        PinnedResolver,
        RustlsHttpsConnector::default(),
        IpPolicy::default(),
        FetchPolicy::default(),
    );
    let response = pinned_fetcher
        .fetch(&request("/payload"), &authority())
        .expect("real TLS fetch to the validated address must succeed");
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"real tls payload");

    // This resolver uses the production OS path on both hops. It rewrites only
    // the controlled DNS fixture after the first lookup, modeling a name that
    // changes to a private address between redirect hops.
    replace_dns_target(&dns_hosts_path, SERVER_IP)
        .expect("controlled DNS hosts file must be mutable");
    dns.reload().expect("controlled DNS answer must reload");
    let rebinding_fetcher = PublicFetcher::new(
        RebindingSystemResolver {
            dns_hosts_path,
            dns_process_id: dns.0.id(),
            calls: Mutex::new(0),
        },
        RustlsHttpsConnector::default(),
        IpPolicy::default(),
        FetchPolicy::default(),
    );
    assert_eq!(
        rebinding_fetcher.fetch(&request("/redirect"), &authority()),
        Err(FetchError::IpPolicy(IpPolicyError::DeniedAnswer))
    );
}
