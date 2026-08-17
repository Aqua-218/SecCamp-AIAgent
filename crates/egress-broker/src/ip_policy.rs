//! Destination IP policy for public egress.
//!
//! DNS answers are treated as a set, not as a best-effort list. If any answer
//! is private, special-purpose, or host-denied, the complete answer is
//! rejected. This prevents an attacker from winning a race by making a later
//! connector choose an address that was not part of the validated public set.

use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// An inclusive CIDR range used by the host's deny policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpRange {
    network: IpAddr,
    prefix_length: u8,
}

impl IpRange {
    /// Creates a CIDR range and canonicalizes its network bits.
    ///
    /// # Errors
    ///
    /// Returns [`IpRangeError::PrefixTooLarge`] when the prefix is wider than
    /// the address family permits.
    pub fn new(network: IpAddr, prefix_length: u8) -> Result<Self, IpRangeError> {
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_length > max {
            return Err(IpRangeError::PrefixTooLarge { prefix_length, max });
        }
        Ok(Self {
            network: mask_address(network, prefix_length),
            prefix_length,
        })
    }

    /// Returns whether `address` is inside this range.
    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                mask_v4(address, self.prefix_length) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                mask_v6(address, self.prefix_length) == u128::from(network)
            }
            _ => false,
        }
    }
}

/// Why a CIDR range could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRangeError {
    /// The prefix is wider than the selected address family.
    PrefixTooLarge {
        /// Supplied CIDR prefix length.
        prefix_length: u8,
        /// Maximum prefix length for the address family.
        max: u8,
    },
}

impl fmt::Display for IpRangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixTooLarge { prefix_length, max } => write!(
                formatter,
                "IP range prefix length {prefix_length} exceeds the address family limit {max}"
            ),
        }
    }
}

impl Error for IpRangeError {}

/// The default destination policy for unauthenticated public HTTPS fetches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPolicy {
    host_denied_ranges: Vec<IpRange>,
}

impl Default for IpPolicy {
    fn default() -> Self {
        Self::strict(Vec::new()).expect("built-in IP ranges are valid")
    }
}

impl IpPolicy {
    /// Creates the strict policy with additional host-managed deny ranges.
    ///
    /// Built-in special-purpose ranges remain active even when the caller
    /// supplies an empty custom list. This keeps a host configuration from
    /// accidentally disabling SSRF protections.
    ///
    /// # Errors
    ///
    /// Returns the first invalid custom range.
    pub fn strict(
        additional_ranges: impl IntoIterator<Item = IpRange>,
    ) -> Result<Self, IpRangeError> {
        let mut host_denied_ranges = built_in_denied_ranges()?;
        host_denied_ranges.extend(additional_ranges);
        Ok(Self { host_denied_ranges })
    }

    /// Returns whether the address is covered by a host-managed deny range.
    #[must_use]
    pub fn is_host_denied(&self, address: IpAddr) -> bool {
        self.host_denied_ranges
            .iter()
            .copied()
            .any(|range| range.contains(address))
    }

    /// Validates one complete DNS answer and returns its first safe address.
    ///
    /// # Errors
    ///
    /// Rejects an empty answer and rejects the entire answer if any address is
    /// private, loopback, link-local, multicast, metadata, mapped, or denied
    /// by the host policy.
    pub fn validate_dns_answer(&self, addresses: &[IpAddr]) -> Result<IpAddr, IpPolicyError> {
        let first = addresses
            .first()
            .copied()
            .ok_or(IpPolicyError::EmptyAnswer)?;
        if addresses
            .iter()
            .copied()
            .any(|address| self.is_denied(address))
        {
            return Err(IpPolicyError::DeniedAnswer);
        }
        Ok(first)
    }

    fn is_denied(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => self.is_host_denied(IpAddr::V4(address)),
            IpAddr::V6(address) => {
                // Mapped and IPv4-compatible IPv6 forms must never reach the
                // connector, even when their embedded IPv4 address is public.
                address.to_ipv4().is_some() || self.is_host_denied(IpAddr::V6(address))
            }
        }
    }
}

/// Why a DNS answer cannot be used for public egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPolicyError {
    /// The resolver returned no addresses.
    EmptyAnswer,
    /// At least one address in the complete answer is not public.
    DeniedAnswer,
}

impl fmt::Display for IpPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAnswer => {
                formatter.write_str("DNS returned no address for the requested host")
            }
            Self::DeniedAnswer => formatter.write_str(
                "DNS answer contains a private, special-purpose, or host-denied address",
            ),
        }
    }
}

impl Error for IpPolicyError {}

fn built_in_denied_ranges() -> Result<Vec<IpRange>, IpRangeError> {
    let ipv4 = [
        (Ipv4Addr::UNSPECIFIED, 8),
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(127, 0, 0, 0), 8),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 0, 0, 0), 24),
        (Ipv4Addr::new(192, 0, 2, 0), 24),
        (Ipv4Addr::new(192, 31, 196, 0), 24),
        (Ipv4Addr::new(192, 52, 193, 0), 24),
        (Ipv4Addr::new(192, 88, 99, 0), 24),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(192, 175, 48, 0), 24),
        (Ipv4Addr::new(198, 18, 0, 0), 15),
        (Ipv4Addr::new(198, 51, 100, 0), 24),
        (Ipv4Addr::new(203, 0, 113, 0), 24),
        (Ipv4Addr::new(224, 0, 0, 0), 4),
        (Ipv4Addr::new(240, 0, 0, 0), 4),
    ];
    let ipv6 = [
        (Ipv6Addr::UNSPECIFIED, 96),
        (Ipv6Addr::UNSPECIFIED, 128),
        (Ipv6Addr::LOCALHOST, 128),
        (Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
        (Ipv6Addr::new(0x0064, 0xff9b, 0, 1, 0, 0, 0, 0), 48),
        (Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64),
        (Ipv6Addr::new(0x0100, 0, 0, 1, 0, 0, 0, 0), 64),
        // The IANA IETF Protocol Assignments supernet contains Teredo, benchmarking, AMT,
        // AS112, ORCHID, DETs, and their future more-specific registrations.
        (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
        (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
        (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
        (Ipv6Addr::new(0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0), 48),
        (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
        (Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16),
        (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
        (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
        (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
    ];
    ipv4.into_iter()
        .map(|(network, prefix)| IpRange::new(IpAddr::V4(network), prefix))
        .chain(
            ipv6.into_iter()
                .map(|(network, prefix)| IpRange::new(IpAddr::V6(network), prefix)),
        )
        .collect()
}

fn mask_address(address: IpAddr, prefix_length: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => IpAddr::V4(Ipv4Addr::from(mask_v4(address, prefix_length))),
        IpAddr::V6(address) => IpAddr::V6(Ipv6Addr::from(mask_v6(address, prefix_length))),
    }
}

fn mask_v4(address: Ipv4Addr, prefix_length: u8) -> u32 {
    let value = u32::from(address);
    if prefix_length == 0 {
        0
    } else {
        value
            & u32::MAX
                .checked_shl(u32::from(32 - prefix_length))
                .unwrap_or(0)
    }
}

fn mask_v6(address: Ipv6Addr, prefix_length: u8) -> u128 {
    let value = u128::from(address);
    if prefix_length == 0 {
        0
    } else {
        value
            & u128::MAX
                .checked_shl(u32::from(128 - prefix_length))
                .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{IpPolicy, IpPolicyError, IpRange};

    // Requirement: every DNS answer is rejected if any member is internal.
    // Category: security/error/boundary. Risk: critical.
    #[test]
    fn dns_answer_rejects_private_and_mixed_public_private_addresses() {
        let policy = IpPolicy::default();
        assert_eq!(
            policy.validate_dns_answer(&[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))]),
            Err(IpPolicyError::DeniedAnswer)
        );
        assert_eq!(
            policy.validate_dns_answer(&[
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
            ]),
            Err(IpPolicyError::DeniedAnswer)
        );
    }

    // Requirement: loopback, link-local, multicast, special, and mapped addresses are denied.
    // Category: security/equivalence classes. Risk: critical.
    #[test]
    fn special_purpose_and_mapped_addresses_are_denied_without_echoing_the_ip() {
        let policy = IpPolicy::default();
        let addresses = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "::ffff:127.0.0.1"
                .parse()
                .expect("mapped IPv6 fixture is valid"),
            "::ffff:93.184.216.34"
                .parse()
                .expect("public mapped IPv6 fixture is valid"),
            "64:ff9b::c000:0201"
                .parse()
                .expect("NAT64 fixture is valid"),
        ];
        for address in addresses {
            let error = policy
                .validate_dns_answer(&[address])
                .expect_err("special-purpose address must be rejected");
            assert_eq!(
                error.to_string(),
                "DNS answer contains a private, special-purpose, or host-denied address"
            );
        }
    }

    #[test]
    fn current_iana_special_purpose_registrations_are_all_denied() {
        let policy = IpPolicy::default();
        for address in [
            "192.31.196.1",
            "192.52.193.1",
            "192.175.48.1",
            "100:0:0:1::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
            "2620:4f:8000::1",
            "3fff::1",
            "5f00::1",
        ] {
            let address = address.parse().expect("IANA registry fixture must parse");
            assert_eq!(
                policy.validate_dns_answer(&[address]),
                Err(IpPolicyError::DeniedAnswer),
                "{address} must remain denied"
            );
        }
    }

    // Requirement: host-managed ranges extend, but cannot replace, built-in deny ranges.
    // Category: configuration/boundary. Risk: high.
    #[test]
    fn custom_host_deny_range_is_enforced() {
        let range = IpRange::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24)
            .expect("custom range prefix is valid");
        let policy = IpPolicy::strict([range]).expect("custom policy must build");
        assert_eq!(
            policy.validate_dns_answer(&[IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]),
            Err(IpPolicyError::DeniedAnswer)
        );
    }
}
