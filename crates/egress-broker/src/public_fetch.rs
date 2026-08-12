//! Bounded unauthenticated HTTPS GET/HEAD fetching.
//!
//! Resolver and connector are explicit traits so policy tests never need a
//! network. The production connector creates a request-specific Reqwest
//! client with rustls, pins the connection to the already validated address,
//! and disables automatic redirects. Every redirect starts a fresh policy
//! check and DNS lookup.

use std::{
    error::Error,
    fmt,
    io::Read,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::{Duration, Instant},
};

use authority_core::http::{
    CanonicalHost, CanonicalUrlPath, HttpFetchAuthority, HttpFetchMethod, HttpFetchRequest,
    http_fetch_matches,
};
use egress_protocol::response::PublicWireResponse;
use reqwest::blocking::Client;
use url::Url;

use crate::ip_policy::{IpPolicy, IpPolicyError};

/// The maximum number of redirect responses followed for one fetch.
pub const DEFAULT_MAX_REDIRECTS: u8 = 5;
/// The maximum body returned by the broker regardless of the capability cap.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
/// The port allowed for every public HTTPS request.
pub const HTTPS_PORT: u16 = 443;
const MAX_REDIRECT_LOCATION_BYTES: usize = 8 * 1024;
const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);

/// A validated host/path pair supplied to a connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchTarget {
    host: CanonicalHost,
    path: CanonicalUrlPath,
}

impl FetchTarget {
    fn new(host: CanonicalHost, path: CanonicalUrlPath) -> Self {
        Self { host, path }
    }

    /// Returns the canonical TLS name and HTTP authority host.
    #[must_use]
    pub fn host(&self) -> &CanonicalHost {
        &self.host
    }

    /// Returns the canonical origin-form path.
    #[must_use]
    pub fn path(&self) -> &CanonicalUrlPath {
        &self.path
    }
}

/// One raw response returned by a connector before body-cap enforcement.
pub struct ConnectorResponse {
    /// HTTP status code received from the upstream server.
    pub status: u16,
    /// A single validated textual Location value, if the connector received one.
    pub location: Option<String>,
    /// The response body stream. The fetcher owns and bounds its consumption.
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for ConnectorResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorResponse")
            .field("status", &self.status)
            .field("location", &self.location)
            .field("body", &"<stream>")
            .finish()
    }
}

/// A DNS resolver used by the egress policy.
pub trait Resolver: Send + Sync {
    /// Resolves the exact canonical host for one connection attempt.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError`] when the host cannot be resolved.
    fn resolve(&self, host: &CanonicalHost) -> Result<Vec<IpAddr>, ResolveError>;
}

/// A connector that must connect only to the supplied validated address.
pub trait HttpsConnector: Send + Sync {
    /// Sends one GET or HEAD request with no caller-controlled headers/body.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError`] when the bounded connection or request fails.
    fn send(
        &self,
        target: &FetchTarget,
        address: SocketAddr,
        method: HttpFetchMethod,
        timeout: Duration,
    ) -> Result<ConnectorResponse, ConnectorError>;
}

/// The host resolver used by the production adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &CanonicalHost) -> Result<Vec<IpAddr>, ResolveError> {
        (host.as_str(), HTTPS_PORT)
            .to_socket_addrs()
            .map(|addresses| addresses.map(|address| address.ip()).collect())
            .map_err(|_| ResolveError::LookupFailed)
    }
}

/// The rustls-backed production HTTPS connector.
#[derive(Debug, Clone, Copy)]
pub struct RustlsHttpsConnector {
    /// Maximum time allowed for TCP/TLS connection establishment.
    connect_timeout: Duration,
}

impl RustlsHttpsConnector {
    /// Creates a connector with the supplied connection timeout.
    #[must_use]
    pub const fn new(connect_timeout: Duration) -> Self {
        Self { connect_timeout }
    }
}

impl Default for RustlsHttpsConnector {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

impl HttpsConnector for RustlsHttpsConnector {
    fn send(
        &self,
        target: &FetchTarget,
        address: SocketAddr,
        method: HttpFetchMethod,
        timeout: Duration,
    ) -> Result<ConnectorResponse, ConnectorError> {
        if address.port() != HTTPS_PORT {
            return Err(ConnectorError::RequestFailed);
        }
        let url = format!("https://{}{}", target.host(), target.path());
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(self.connect_timeout)
            .timeout(timeout)
            .resolve(target.host().as_str(), address)
            .build()
            .map_err(|_| ConnectorError::ClientBuildFailed)?;
        let response = match method {
            HttpFetchMethod::Get => client.get(url),
            HttpFetchMethod::Head => client.head(url),
        }
        .send()
        .map_err(|_| ConnectorError::RequestFailed)?;
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()
            .map_err(|_| ConnectorError::InvalidLocationHeader)?;
        Ok(ConnectorResponse {
            status: response.status().as_u16(),
            location,
            body: Box::new(response),
        })
    }
}

/// Limits applied to each public fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchPolicy {
    /// Maximum redirect hops.
    pub max_redirects: u8,
    /// Host-wide upper bound on one response body.
    pub max_response_bytes: u64,
    /// Total timeout for each connector attempt.
    pub total_timeout: Duration,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            max_redirects: DEFAULT_MAX_REDIRECTS,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            total_timeout: Duration::from_secs(60),
        }
    }
}

/// A complete public response after streaming-cap enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicResponse {
    wire: PublicWireResponse,
}

impl PublicResponse {
    /// Constructs a response only when it already satisfies the canonical wire contract.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::InvalidResponse`] when the status, canonical
    /// destination, or body cannot be represented by the broker response wire.
    pub fn new(
        status: u16,
        host: CanonicalHost,
        path: CanonicalUrlPath,
        body: Vec<u8>,
    ) -> Result<Self, FetchError> {
        PublicWireResponse::new(status, host, path, body)
            .map(|wire| Self { wire })
            .map_err(|_| FetchError::InvalidResponse)
    }

    /// Returns the final HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.wire.status()
    }

    /// Returns the final canonical host after redirect processing.
    #[must_use]
    pub const fn host(&self) -> &CanonicalHost {
        self.wire.host()
    }

    /// Returns the final canonical path after redirect processing.
    #[must_use]
    pub const fn path(&self) -> &CanonicalUrlPath {
        self.wire.path()
    }

    /// Returns body bytes bounded by both authority and canonical wire policy.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.wire.body()
    }

    /// Checks that an extension response remains within the selected request and authority.
    pub(crate) fn validate_dispatch(
        &self,
        request: &HttpFetchRequest,
        authority: &HttpFetchAuthority,
    ) -> bool {
        let body_fits = u64::try_from(self.body().len())
            .is_ok_and(|body_bytes| body_bytes <= request.max_response_bytes());
        let method_body_matches =
            request.method() != HttpFetchMethod::Head || self.body().is_empty();
        let final_request = HttpFetchRequest::new(
            request.method(),
            self.host().clone(),
            self.path().clone(),
            request.max_response_bytes(),
        );
        body_fits && method_body_matches && http_fetch_matches(authority, &final_request)
    }

    pub(crate) fn into_wire(self) -> PublicWireResponse {
        self.wire
    }
}

/// DNS resolver failures that do not disclose the queried address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    /// The resolver could not provide an answer.
    LookupFailed,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DNS resolution failed for the requested host")
    }
}

impl Error for ResolveError {}

/// Connector failures kept opaque so transport details and credentials cannot leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorError {
    /// The fixed rustls client could not be constructed.
    ClientBuildFailed,
    /// The request could not be completed.
    RequestFailed,
    /// The upstream Location header was not valid text.
    InvalidLocationHeader,
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ClientBuildFailed => "HTTPS client could not be constructed",
            Self::RequestFailed => "HTTPS request failed",
            Self::InvalidLocationHeader => "upstream Location header was not valid text",
        };
        formatter.write_str(message)
    }
}

impl Error for ConnectorError {}

/// Why a public fetch was rejected or could not complete safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The request used a method or response cap outside the broker policy.
    OperationRejected,
    /// A redirect target was not a canonical HTTPS origin on port 443.
    RedirectRejected,
    /// The redirect chain exceeded the configured hop limit.
    RedirectLimitExceeded,
    /// A redirect did not provide a usable Location value.
    MissingRedirectLocation,
    /// Resolver failed for a connection attempt.
    Resolve(ResolveError),
    /// The complete DNS answer did not pass the public IP policy.
    IpPolicy(IpPolicyError),
    /// The connector failed before a response was received.
    Connect(ConnectorError),
    /// A response exceeded its byte cap while it was being read.
    ResponseTooLarge {
        /// Maximum bytes permitted by the request and host policy.
        limit: u64,
    },
    /// The complete redirecting fetch exceeded its total time budget.
    OverallTimeout,
    /// Reading the response stream failed.
    ResponseRead,
    /// The completed response cannot be represented by the canonical broker wire.
    InvalidResponse,
}

impl fmt::Display for FetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperationRejected => {
                formatter.write_str("public fetch operation is outside the broker policy")
            }
            Self::RedirectRejected => {
                formatter.write_str("redirect target is not an allowed canonical HTTPS origin")
            }
            Self::RedirectLimitExceeded => {
                formatter.write_str("redirect chain exceeded the broker hop limit")
            }
            Self::MissingRedirectLocation => {
                formatter.write_str("redirect response did not provide a Location value")
            }
            Self::Resolve(error) => error.fmt(formatter),
            Self::IpPolicy(error) => error.fmt(formatter),
            Self::Connect(error) => error.fmt(formatter),
            Self::ResponseTooLarge { limit } => {
                write!(formatter, "response exceeded the {limit}-byte broker limit")
            }
            Self::OverallTimeout => formatter.write_str("public fetch exceeded its total timeout"),
            Self::ResponseRead => formatter.write_str("reading the HTTPS response failed"),
            Self::InvalidResponse => {
                formatter.write_str("public response is outside the canonical broker wire")
            }
        }
    }
}

impl Error for FetchError {}

/// A public fetch adapter with deterministic resolver and connector seams.
pub struct PublicFetcher<R, C> {
    resolver: R,
    connector: C,
    ip_policy: IpPolicy,
    policy: FetchPolicy,
}

impl<R, C> PublicFetcher<R, C>
where
    R: Resolver,
    C: HttpsConnector,
{
    /// Creates a fetcher with explicit network-policy dependencies.
    #[must_use]
    pub const fn new(resolver: R, connector: C, ip_policy: IpPolicy, policy: FetchPolicy) -> Self {
        Self {
            resolver,
            connector,
            ip_policy,
            policy,
        }
    }

    /// Fetches a typed request after checking every redirect against authority.
    ///
    /// # Errors
    ///
    /// Returns an error before connector invocation when the method, target,
    /// DNS answer, redirect, or response size violates policy.
    pub fn fetch(
        &self,
        request: &HttpFetchRequest,
        authority: &HttpFetchAuthority,
    ) -> Result<PublicResponse, FetchError> {
        let max_response_bytes = self
            .policy
            .max_response_bytes
            .min(DEFAULT_MAX_RESPONSE_BYTES);
        let max_redirects = self.policy.max_redirects.min(DEFAULT_MAX_REDIRECTS);
        let total_timeout = self.policy.total_timeout.min(MAX_TOTAL_TIMEOUT);
        if !matches!(
            request.method(),
            HttpFetchMethod::Get | HttpFetchMethod::Head
        ) || request.max_response_bytes() > max_response_bytes
        {
            return Err(FetchError::OperationRejected);
        }

        let deadline = Instant::now().checked_add(total_timeout);
        let mut target = FetchTarget::new(request.host().clone(), request.path().clone());
        let mut redirects = 0;
        loop {
            let remaining = deadline.map_or(Duration::ZERO, |deadline| {
                deadline.saturating_duration_since(Instant::now())
            });
            if remaining.is_zero() {
                return Err(FetchError::OverallTimeout);
            }
            let hop_request = HttpFetchRequest::new(
                request.method(),
                target.host().clone(),
                target.path().clone(),
                request.max_response_bytes(),
            );
            if !http_fetch_matches(authority, &hop_request) {
                return Err(FetchError::RedirectRejected);
            }
            let addresses = self
                .resolver
                .resolve(target.host())
                .map_err(FetchError::Resolve)?;
            let address = self
                .ip_policy
                .validate_dns_answer(&addresses)
                .map_err(FetchError::IpPolicy)?;
            let response = self
                .connector
                .send(
                    &target,
                    SocketAddr::new(address, HTTPS_PORT),
                    request.method(),
                    remaining,
                )
                .map_err(FetchError::Connect)?;
            if is_redirect(response.status) {
                if redirects >= max_redirects {
                    return Err(FetchError::RedirectLimitExceeded);
                }
                let location = response
                    .location
                    .ok_or(FetchError::MissingRedirectLocation)?;
                if location.len() > MAX_REDIRECT_LOCATION_BYTES {
                    return Err(FetchError::RedirectRejected);
                }
                target = redirect_target(&target, &location)?;
                redirects = redirects.saturating_add(1);
                continue;
            }
            let body = if request.method() == HttpFetchMethod::Head {
                Vec::new()
            } else {
                read_bounded(response.body, request.max_response_bytes(), deadline)?
            };
            return PublicResponse::new(response.status, target.host, target.path, body);
        }
    }
}

fn read_bounded(
    mut body: Box<dyn Read + Send>,
    limit: u64,
    deadline: Option<Instant>,
) -> Result<Vec<u8>, FetchError> {
    let initial_capacity = usize::try_from(limit.min(8 * 1024)).unwrap_or(8 * 1024);
    let mut output = Vec::with_capacity(initial_capacity);
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(FetchError::OverallTimeout);
        }
        let read = body
            .read(&mut buffer)
            .map_err(|_| FetchError::ResponseRead)?;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(FetchError::OverallTimeout);
        }
        if read == 0 {
            return Ok(output);
        }
        let next_len = output.len().saturating_add(read);
        if u64::try_from(next_len).map_or(true, |length| length > limit) {
            return Err(FetchError::ResponseTooLarge { limit });
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn redirect_target(current: &FetchTarget, location: &str) -> Result<FetchTarget, FetchError> {
    if location.is_empty()
        || location.contains('%')
        || location.contains('\\')
        || location.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(FetchError::RedirectRejected);
    }
    let base = Url::parse(&format!("https://{}{}", current.host(), current.path()))
        .map_err(|_| FetchError::RedirectRejected)?;
    let url = base
        .join(location)
        .map_err(|_| FetchError::RedirectRejected)?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.port().is_some_and(|port| port != HTTPS_PORT)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(FetchError::RedirectRejected);
    }
    let host = url
        .host_str()
        .ok_or(FetchError::RedirectRejected)
        .and_then(|value| CanonicalHost::new(value).map_err(|_| FetchError::RedirectRejected))?;
    let url_path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let path = CanonicalUrlPath::new(url_path).map_err(|_| FetchError::RedirectRejected)?;
    Ok(FetchTarget::new(host, path))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::{Cursor, Read},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use authority_core::http::{
        CanonicalHost, CanonicalUrlPath, HttpFetchAuthority, HttpFetchMethods, UrlPathPattern,
    };
    use egress_protocol::response::MAX_PUBLIC_WIRE_BODY_BYTES;

    use super::{
        ConnectorError, ConnectorResponse, FetchError, FetchPolicy, FetchTarget, HttpsConnector,
        PublicFetcher, PublicResponse, Resolver, read_bounded,
    };
    use crate::ip_policy::IpPolicy;

    fn request(path: &str, cap: u64) -> authority_core::http::HttpFetchRequest {
        request_with_method(authority_core::http::HttpFetchMethod::Get, path, cap)
    }

    fn request_with_method(
        method: authority_core::http::HttpFetchMethod,
        path: &str,
        cap: u64,
    ) -> authority_core::http::HttpFetchRequest {
        authority_core::http::HttpFetchRequest::new(
            method,
            CanonicalHost::new("public.example").expect("fixture host is valid"),
            CanonicalUrlPath::new(path).expect("fixture path is valid"),
            cap,
        )
    }

    fn authority(path: &str, cap: u64) -> HttpFetchAuthority {
        authority_with_method(authority_core::http::HttpFetchMethod::Get, path, cap)
    }

    fn authority_with_method(
        method: authority_core::http::HttpFetchMethod,
        path: &str,
        cap: u64,
    ) -> HttpFetchAuthority {
        HttpFetchAuthority::new(
            HttpFetchMethods::only(method),
            CanonicalHost::new("public.example").expect("fixture host is valid"),
            UrlPathPattern::Prefix(CanonicalUrlPath::new(path).expect("fixture path is valid")),
            cap,
        )
    }

    #[derive(Clone)]
    struct QueueResolver(Arc<Mutex<VecDeque<Vec<IpAddr>>>>);

    impl Resolver for QueueResolver {
        fn resolve(&self, _host: &CanonicalHost) -> Result<Vec<IpAddr>, super::ResolveError> {
            self.0
                .lock()
                .expect("resolver mutex is not poisoned")
                .pop_front()
                .ok_or(super::ResolveError::LookupFailed)
        }
    }

    type ResponseFixture = (u16, Option<String>, Vec<u8>);
    type TargetLog = Arc<Mutex<Vec<(String, SocketAddr)>>>;

    struct MockConnector {
        responses: Mutex<VecDeque<ResponseFixture>>,
        targets: Arc<Mutex<Vec<(String, SocketAddr)>>>,
    }

    impl HttpsConnector for MockConnector {
        fn send(
            &self,
            target: &FetchTarget,
            address: SocketAddr,
            _method: authority_core::http::HttpFetchMethod,
            _timeout: Duration,
        ) -> Result<ConnectorResponse, ConnectorError> {
            self.targets
                .lock()
                .expect("target mutex is not poisoned")
                .push((target.path().to_string(), address));
            let (status, location, body) = self
                .responses
                .lock()
                .expect("response mutex is not poisoned")
                .pop_front()
                .ok_or(ConnectorError::RequestFailed)?;
            Ok(ConnectorResponse {
                status,
                location,
                body: Box::new(Cursor::new(body)),
            })
        }
    }

    fn fetcher(
        resolutions: Vec<Vec<IpAddr>>,
        responses: Vec<(u16, Option<&str>, Vec<u8>)>,
    ) -> (PublicFetcher<QueueResolver, MockConnector>, TargetLog) {
        let targets = Arc::new(Mutex::new(Vec::new()));
        let connector = MockConnector {
            responses: Mutex::new(
                responses
                    .into_iter()
                    .map(|(status, location, body)| (status, location.map(str::to_owned), body))
                    .collect(),
            ),
            targets: targets.clone(),
        };
        let resolver = QueueResolver(Arc::new(Mutex::new(resolutions.into_iter().collect())));
        (
            PublicFetcher::new(
                resolver,
                connector,
                IpPolicy::default(),
                FetchPolicy::default(),
            ),
            targets,
        )
    }

    // Requirement: a normal public GET returns the bounded body through a mock connector.
    // Category: normal/contract. Risk: high.
    #[test]
    fn public_get_returns_status_body_and_validated_destination() {
        let (fetcher, targets) = fetcher(
            vec![vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]],
            vec![(200, None, b"hello".to_vec())],
        );
        let response = fetcher
            .fetch(&request("/guide", 32), &authority("/guide", 32))
            .expect("public GET should succeed");
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"hello");
        assert_eq!(
            targets
                .lock()
                .expect("target mutex is not poisoned")
                .as_slice(),
            &[(
                "/guide".to_owned(),
                "93.184.216.34:443"
                    .parse()
                    .expect("fixture address is valid")
            )]
        );
    }

    // Requirement: HEAD is supported without consuming or returning a response body.
    // Category: normal/resource. Risk: high.
    #[test]
    fn public_head_does_not_read_or_return_the_response_body() {
        let (fetcher, _) = fetcher(
            vec![vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]],
            vec![(200, None, b"body must not be consumed".to_vec())],
        );
        let response = fetcher
            .fetch(
                &request_with_method(authority_core::http::HttpFetchMethod::Head, "/guide", 4),
                &authority_with_method(authority_core::http::HttpFetchMethod::Head, "/guide", 4),
            )
            .expect("public HEAD should succeed");
        assert_eq!(response.status(), 200);
        assert!(response.body().is_empty());
    }

    // Requirement: every constructible successful response fits the canonical response wire.
    // Category: boundary/security. Risk: critical.
    #[test]
    fn public_response_constructor_rejects_unencodable_successes() {
        let host = CanonicalHost::new("public.example").expect("fixture host is valid");
        let path = CanonicalUrlPath::new("/guide").expect("fixture path is valid");
        assert_eq!(
            PublicResponse::new(99, host.clone(), path.clone(), Vec::new()),
            Err(FetchError::InvalidResponse)
        );
        let oversized = usize::try_from(MAX_PUBLIC_WIRE_BODY_BYTES)
            .expect("wire cap fits the test address space")
            + 1;
        assert_eq!(
            PublicResponse::new(200, host, path, vec![0; oversized]),
            Err(FetchError::InvalidResponse)
        );
    }

    // Requirement: an extension response remains inside the admitted request and authority.
    // Category: boundary/security/accounting. Risk: critical.
    #[test]
    fn public_response_dispatch_validation_rejects_oversize_and_unauthorized_output() {
        let admitted_request = request("/guide", 4);
        let admitted_authority = authority("/guide", 4);
        let host = CanonicalHost::new("public.example").expect("fixture host is valid");
        let path = CanonicalUrlPath::new("/guide").expect("fixture path is valid");
        let valid = PublicResponse::new(200, host.clone(), path, b"okay".to_vec())
            .expect("fixture response is wire valid");
        assert!(valid.validate_dispatch(&admitted_request, &admitted_authority));

        let oversized = PublicResponse::new(
            200,
            host.clone(),
            CanonicalUrlPath::new("/guide").expect("fixture path is valid"),
            b"large".to_vec(),
        )
        .expect("fixture response is wire valid");
        assert!(!oversized.validate_dispatch(&admitted_request, &admitted_authority));

        let outside = PublicResponse::new(
            200,
            host,
            CanonicalUrlPath::new("/outside").expect("fixture path is valid"),
            Vec::new(),
        )
        .expect("fixture response is wire valid");
        assert!(!outside.validate_dispatch(&admitted_request, &admitted_authority));

        let head_request = authority_core::http::HttpFetchRequest::new(
            authority_core::http::HttpFetchMethod::Head,
            CanonicalHost::new("public.example").expect("fixture host is valid"),
            CanonicalUrlPath::new("/guide").expect("fixture path is valid"),
            4,
        );
        let head_body = PublicResponse::new(
            200,
            CanonicalHost::new("public.example").expect("fixture host is valid"),
            CanonicalUrlPath::new("/guide").expect("fixture path is valid"),
            b"body".to_vec(),
        )
        .expect("fixture response is wire valid");
        assert!(!head_body.validate_dispatch(
            &head_request,
            &authority_with_method(authority_core::http::HttpFetchMethod::Head, "/guide", 4,)
        ));
    }

    // Requirement: every redirect re-resolves and re-checks the capability path.
    // Category: state/security. Risk: critical.
    #[test]
    fn redirect_re_resolves_and_rejects_dns_rebinding_to_private_address() {
        let (fetcher, _) = fetcher(
            vec![
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            ],
            vec![(302, Some("/next"), Vec::new())],
        );
        assert_eq!(
            fetcher.fetch(&request("/guide", 32), &authority("/", 32)),
            Err(FetchError::IpPolicy(
                crate::ip_policy::IpPolicyError::DeniedAnswer
            ))
        );
    }

    // Requirement: redirect destinations outside the authorized path are rejected before I/O.
    // Category: authorization/security. Risk: critical.
    #[test]
    fn redirect_outside_authority_is_rejected_before_second_connector_call() {
        let (fetcher, targets) = fetcher(
            vec![vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]],
            vec![(302, Some("/outside"), Vec::new())],
        );
        assert_eq!(
            fetcher.fetch(&request("/guide", 32), &authority("/guide", 32)),
            Err(FetchError::RedirectRejected)
        );
        assert_eq!(
            targets.lock().expect("target mutex is not poisoned").len(),
            1
        );
    }

    // Requirement: response bytes are capped while streaming, not after buffering.
    // Category: boundary/resource exhaustion. Risk: high.
    #[test]
    fn oversized_response_is_rejected_at_the_first_cap_exceeding_read() {
        let (fetcher, _) = fetcher(
            vec![vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]],
            vec![(200, None, b"12345".to_vec())],
        );
        assert_eq!(
            fetcher.fetch(&request("/guide", 4), &authority("/guide", 4)),
            Err(FetchError::ResponseTooLarge { limit: 4 })
        );
    }

    // Requirement: the broker never follows HTTP, userinfo, query, or fragment redirects.
    // Category: security/input validation. Risk: high.
    #[test]
    fn unsafe_redirect_forms_are_rejected() {
        for location in [
            "http://public.example/next",
            "https://u:p@public.example/next",
            "/next?secret=1",
            "/next#fragment",
        ] {
            let (fetcher, _) = fetcher(
                vec![vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]],
                vec![(302, Some(location), Vec::new())],
            );
            assert_eq!(
                fetcher.fetch(&request("/guide", 32), &authority("/", 32)),
                Err(FetchError::RedirectRejected),
                "redirect {location:?} must be rejected"
            );
        }
    }

    // Requirement: redirects use one canonical, unencoded origin-form path.
    // Category: input validation/security. Risk: high.
    #[test]
    fn redirect_percent_encoding_and_path_normalization_are_rejected() {
        for location in ["/next%2Fsecret", "/next/", "/next\\secret"] {
            let (fetcher, targets) = fetcher(
                vec![vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]],
                vec![(302, Some(location), Vec::new())],
            );
            assert_eq!(
                fetcher.fetch(&request("/guide", 32), &authority("/", 32)),
                Err(FetchError::RedirectRejected),
                "redirect {location:?} must not introduce an alternate path spelling"
            );
            assert_eq!(
                targets.lock().expect("target mutex is not poisoned").len(),
                1
            );
        }
    }

    // Requirement: policy limits remain bounded even when a host supplies oversized configuration.
    // Category: boundary/resource. Risk: high.
    #[test]
    fn oversized_policy_is_clamped_before_request_admission() {
        let targets = Arc::new(Mutex::new(Vec::new()));
        let fetcher = PublicFetcher::new(
            QueueResolver(Arc::new(Mutex::new(
                vec![vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]]
                    .into_iter()
                    .collect(),
            ))),
            MockConnector {
                responses: Mutex::new(VecDeque::from([(200, None, b"bounded".to_vec())])),
                targets,
            },
            IpPolicy::default(),
            FetchPolicy {
                max_redirects: u8::MAX,
                max_response_bytes: u64::MAX,
                total_timeout: Duration::from_secs(u64::MAX),
            },
        );
        let response = fetcher
            .fetch(&request("/guide", 32), &authority("/guide", 32))
            .expect("request under the hard policy cap should succeed");
        assert_eq!(response.body(), b"bounded");
    }

    struct SlowEmptyReader;

    impl Read for SlowEmptyReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_millis(2));
            Ok(0)
        }
    }

    // Requirement: response draining observes the same total deadline as connection and redirects.
    // Category: timeout/error/resource. Risk: high.
    #[test]
    fn slow_response_reader_is_rejected_after_the_total_deadline() {
        assert_eq!(
            read_bounded(
                Box::new(SlowEmptyReader),
                32,
                Some(Instant::now() + Duration::from_millis(1)),
            ),
            Err(FetchError::OverallTimeout)
        );
    }
}
