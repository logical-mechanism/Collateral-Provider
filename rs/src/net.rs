//! Client-identity extraction. One place decides who the caller is, so bans,
//! metrics authorization, and throttling always agree.

use std::net::IpAddr;

use ipnet::IpNet;

/// Return a validated IP address, or `None` for malformed input.
///
/// Forwarding headers are untrusted text even when they arrive through a
/// trusted proxy. Scoped IPv6 addresses are intentionally rejected: zone IDs
/// are meaningful only on the sender's host and are not valid client
/// identities across an HTTP proxy boundary.
pub fn parse_ip(value: &str) -> Option<IpAddr> {
    if value.is_empty() || value.contains('%') {
        return None;
    }
    value.trim().parse::<IpAddr>().ok()
}

pub fn is_trusted_proxy(ip: &IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|network| network.contains(ip))
}

/// Best-effort client IP extraction.
///
/// Only honors `X-Forwarded-For` when the immediate peer is in `trusted`.
/// When it is, walk the forwarded chain from right to left, skip known proxy
/// hops, and use the first untrusted address as the client. This is important
/// for the common `$proxy_add_x_forwarded_for` configuration: a caller can
/// prefix a fake leftmost value, but the proxy-appended real address remains
/// the rightmost untrusted hop.
///
/// Otherwise returns the validated peer directly — a client connecting
/// without the proxy in front can't spoof their source IP and bypass the
/// per-IP throttle just by setting a header.
///
/// A malformed hop fails closed to the immediate peer rather than looking
/// farther left at values the caller may have supplied. When every supplied
/// hop claims to be a trusted proxy the header never established a client
/// address, so the peer is used rather than the header's leftmost value.
pub fn client_ip(peer: Option<IpAddr>, xff: Option<&str>, trusted: &[IpNet]) -> Option<String> {
    let peer = peer?;
    // Normalized, so "::1" and "0:0:0:0:0:0:0:1" are one throttle key.
    let peer_text = peer.to_string();

    let chain = match xff {
        Some(chain) if !chain.is_empty() => chain,
        _ => return Some(peer_text),
    };
    if !is_trusted_proxy(&peer, trusted) {
        return Some(peer_text);
    }

    for raw_hop in chain.split(',').rev() {
        let Some(hop) = parse_ip(raw_hop) else {
            return Some(peer_text);
        };
        if !is_trusted_proxy(&hop, trusted) {
            return Some(hop.to_string());
        }
    }

    Some(peer_text)
}

/// Parse `TRUSTED_PROXY_IPS`-style entries. Bare IPs become single-host
/// networks; CIDR strings become the corresponding network. Invalid entries
/// are dropped with a warning rather than failing startup.
pub fn parse_networks(entries: &[String]) -> Vec<IpNet> {
    let mut networks = Vec::with_capacity(entries.len());
    for entry in entries {
        let text = entry.trim();
        // `IpNet` needs an explicit prefix, so a bare address is widened to
        // its own /32 or /128 — Python's `ip_network(entry, strict=False)`.
        let parsed = text
            .parse::<IpNet>()
            .ok()
            .or_else(|| text.parse::<IpAddr>().ok().map(IpNet::from));
        match parsed {
            Some(network) => networks.push(network),
            None => tracing::warn!(
                target: "api",
                "Ignoring invalid TRUSTED_PROXY_IPS entry: {:?}",
                entry
            ),
        }
    }
    networks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(entries: &[&str]) -> Vec<IpNet> {
        parse_networks(&entries.iter().map(|e| (*e).to_string()).collect::<Vec<_>>())
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("valid ip")
    }

    fn localhost() -> Vec<IpNet> {
        nets(&["127.0.0.1", "::1"])
    }

    #[test]
    fn parse_ip_normalizes_and_rejects_junk() {
        assert_eq!(parse_ip("2001:0db8:0:0:0:0:0:1"), Some(ip("2001:db8::1")));
        assert_eq!(parse_ip("  1.2.3.4  "), Some(ip("1.2.3.4")));
        assert_eq!(parse_ip(""), None);
        assert_eq!(parse_ip("   "), None);
        assert_eq!(parse_ip("not-an-ip"), None);
        assert_eq!(parse_ip("1.2.3.4:80"), None);
    }

    #[test]
    fn scoped_ipv6_is_rejected_even_though_it_parses_elsewhere() {
        assert_eq!(parse_ip("fe80::1%eth0"), None);
    }

    #[test]
    fn bare_ips_and_cidrs_both_parse_as_networks() {
        let parsed = nets(&["127.0.0.1", "10.0.0.0/8", "::1"]);
        assert_eq!(parsed.len(), 3);
        assert!(is_trusted_proxy(&ip("127.0.0.1"), &parsed));
        assert!(is_trusted_proxy(&ip("10.42.7.99"), &parsed));
        assert!(is_trusted_proxy(&ip("::1"), &parsed));
        assert!(!is_trusted_proxy(&ip("127.0.0.2"), &parsed));
        assert!(!is_trusted_proxy(&ip("8.8.8.8"), &parsed));
    }

    #[test]
    fn invalid_network_entry_is_skipped_not_fatal() {
        let parsed = nets(&["not-an-ip", "127.0.0.1"]);
        assert_eq!(parsed.len(), 1);
        assert!(is_trusted_proxy(&ip("127.0.0.1"), &parsed));
    }

    #[test]
    fn uses_rightmost_untrusted_ip_when_proxy_is_trusted() {
        assert_eq!(
            client_ip(
                Some(ip("127.0.0.1")),
                Some("1.2.3.4, 5.6.7.8"),
                &localhost()
            ),
            Some("5.6.7.8".to_string())
        );
    }

    #[test]
    fn strips_whitespace_around_xff_value() {
        assert_eq!(
            client_ip(
                Some(ip("127.0.0.1")),
                Some("   9.9.9.9   , 1.1.1.1"),
                &localhost()
            ),
            Some("1.1.1.1".to_string())
        );
    }

    #[test]
    fn walks_right_to_left_across_multiple_trusted_proxies() {
        let trusted = nets(&["127.0.0.1", "10.0.0.0/8"]);
        assert_eq!(
            client_ip(
                Some(ip("127.0.0.1")),
                Some("198.51.100.8, 10.9.8.7"),
                &trusted
            ),
            Some("198.51.100.8".to_string())
        );
    }

    #[test]
    fn caller_prefixed_value_is_not_used_as_client() {
        assert_eq!(
            client_ip(
                Some(ip("127.0.0.1")),
                Some("203.0.113.99, 198.51.100.8"),
                &localhost()
            ),
            Some("198.51.100.8".to_string())
        );
    }

    #[test]
    fn malformed_rightmost_hop_falls_back_to_immediate_peer() {
        assert_eq!(
            client_ip(
                Some(ip("127.0.0.1")),
                Some("203.0.113.99, not-an-ip"),
                &localhost()
            ),
            Some("127.0.0.1".to_string())
        );
    }

    #[test]
    fn does_not_use_leftmost_value_when_all_hops_are_trusted() {
        let trusted = nets(&["127.0.0.1", "10.0.0.0/8"]);
        assert_eq!(
            client_ip(Some(ip("127.0.0.1")), Some("10.1.2.3, 10.2.3.4"), &trusted),
            Some("127.0.0.1".to_string())
        );
    }

    #[test]
    fn falls_back_to_peer_when_no_xff() {
        assert_eq!(
            client_ip(Some(ip("2.2.2.2")), None, &localhost()),
            Some("2.2.2.2".to_string())
        );
        assert_eq!(
            client_ip(Some(ip("2.2.2.2")), Some(""), &localhost()),
            Some("2.2.2.2".to_string())
        );
    }

    #[test]
    fn no_peer_means_no_identity() {
        assert_eq!(client_ip(None, Some("1.2.3.4"), &localhost()), None);
    }

    #[test]
    fn peer_is_canonicalized() {
        assert_eq!(
            client_ip(Some(ip("2001:0db8:0:0:0:0:0:1")), None, &localhost()),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn ignores_xff_when_peer_is_not_a_trusted_proxy() {
        // An attacker connecting straight to the service cannot forge XFF to
        // mint a fresh throttle key.
        assert_eq!(
            client_ip(Some(ip("9.9.9.9")), Some("1.2.3.4"), &nets(&["127.0.0.1"])),
            Some("9.9.9.9".to_string())
        );
    }

    #[test]
    fn empty_trusted_list_disables_xff_entirely() {
        assert_eq!(
            client_ip(Some(ip("127.0.0.1")), Some("1.2.3.4"), &[]),
            Some("127.0.0.1".to_string())
        );
    }

    #[test]
    fn ipv6_loopback_proxy_is_trusted_by_default() {
        assert_eq!(
            client_ip(Some(ip("::1")), Some("2001:db8::1"), &localhost()),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn scoped_ipv6_forwarded_hop_falls_back_to_peer() {
        assert_eq!(
            client_ip(Some(ip("127.0.0.1")), Some("fe80::1%eth0"), &localhost()),
            Some("127.0.0.1".to_string())
        );
    }

    #[test]
    fn cidr_block_in_trusted_list_is_honored() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            client_ip(Some(ip("10.42.7.99")), Some("1.2.3.4"), &trusted),
            Some("1.2.3.4".to_string())
        );
        assert_eq!(
            client_ip(Some(ip("8.8.8.8")), Some("1.2.3.4"), &trusted),
            Some("8.8.8.8".to_string())
        );
    }

    #[test]
    fn forwarded_hop_is_normalized_for_the_throttle_key() {
        assert_eq!(
            client_ip(
                Some(ip("127.0.0.1")),
                Some("2001:0DB8:0000:0000:0000:0000:0000:0001"),
                &localhost()
            ),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn a_v4_network_never_matches_a_v6_address() {
        let trusted = nets(&["0.0.0.0/0"]);
        assert!(!is_trusted_proxy(&ip("::1"), &trusted));
    }
}
