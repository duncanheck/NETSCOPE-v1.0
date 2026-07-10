//! # packet — pure packet-header parsing for the capture upgrade (GROWTH G5)
//!
//! The platform-independent half of the pcap/Npcap path: given raw link-layer
//! bytes, extract the L4 conversation (protocol + src/dst socket addrs) and
//! nothing else. Deliberately header-only — the observer captures with a small
//! snaplen, and this parser never looks past the TCP/UDP port words, so payload
//! bytes are structurally unreadable even when a frame carries them.
//!
//! Everything here is pure and tested with handcrafted frames; the libpcap/Npcap
//! device glue lives in [`super::pcap`] behind the `pcap` cargo feature. The
//! [`PacketObserve`] seam is what the engine consumes, so the merge logic tests
//! run on every platform with no capture library at all.

// Without the `pcap` feature the parser has no runtime caller (the unit tests
// still exercise it on every platform); it exists so the pure logic is always
// compiled, reviewed, and tested even where libpcap isn't.
#![cfg_attr(not(feature = "pcap"), allow(dead_code))]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use netscope_protocol::L4Proto;

/// The link-layer framing the capture device produces, reduced to the cases the
/// parser understands. The pcap glue maps libpcap's linktype ints onto this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// Ethernet II (LINKTYPE_ETHERNET = 1), incl. one 802.1Q VLAN tag.
    Ethernet,
    /// BSD loopback: a 4-byte host-order family word (LINKTYPE_NULL = 0,
    /// LINKTYPE_LOOP = 108).
    Null,
    /// Raw IP, no link header (LINKTYPE_RAW = 101, and legacy DLT_RAW = 12/14).
    Raw,
}

/// One observed packet, reduced to its conversation identity + size. `wire_bytes`
/// is the original on-the-wire length from the pcap record header (not the
/// truncated snaplen capture), so byte rates are honest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketSample {
    pub protocol: L4Proto,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub wire_bytes: u64,
}

/// Parse one captured frame. `None` for anything that isn't a well-formed
/// TCP/UDP-over-IP packet we can read the ports of (ARP, ICMP, fragments past
/// the first, truncated captures, unknown link framing) — observation is
/// best-effort by design; dropping a frame only softens a byte count.
pub fn parse(link: LinkKind, data: &[u8], wire_bytes: u64) -> Option<PacketSample> {
    let ip = match link {
        LinkKind::Ethernet => {
            if data.len() < 14 {
                return None;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            match ethertype {
                0x0800 | 0x86dd => &data[14..],
                // One 802.1Q tag: the real ethertype sits 4 bytes later.
                0x8100 if data.len() >= 18 => &data[18..],
                _ => return None,
            }
        }
        // 4-byte family word (host order — accept either byte order since we
        // only skip it; the IP version nibble is the real discriminator).
        LinkKind::Null => {
            if data.len() < 4 {
                return None;
            }
            &data[4..]
        }
        LinkKind::Raw => data,
    };

    if ip.is_empty() {
        return None;
    }
    match ip[0] >> 4 {
        4 => parse_ipv4(ip, wire_bytes),
        6 => parse_ipv6(ip, wire_bytes),
        _ => None,
    }
}

fn parse_ipv4(ip: &[u8], wire_bytes: u64) -> Option<PacketSample> {
    if ip.len() < 20 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    // Non-first fragments carry no L4 header — ports would be garbage.
    let frag_offset = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff;
    if frag_offset != 0 {
        return None;
    }
    let protocol = match ip[9] {
        6 => L4Proto::Tcp,
        17 => L4Proto::Udp,
        _ => return None,
    };
    let src_ip = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
    let (sport, dport) = ports(&ip[ihl..])?;
    Some(PacketSample {
        protocol,
        src: SocketAddr::new(src_ip, sport),
        dst: SocketAddr::new(dst_ip, dport),
        wire_bytes,
    })
}

fn parse_ipv6(ip: &[u8], wire_bytes: u64) -> Option<PacketSample> {
    if ip.len() < 40 {
        return None;
    }
    // Fixed header only: a packet whose first next-header is an extension
    // (fragments, hop-by-hop, …) is skipped rather than chased — rare on the
    // conversations we care about, and best-effort is the contract.
    let protocol = match ip[6] {
        6 => L4Proto::Tcp,
        17 => L4Proto::Udp,
        _ => return None,
    };
    let mut src = [0u8; 16];
    src.copy_from_slice(&ip[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&ip[24..40]);
    let (sport, dport) = ports(&ip[40..])?;
    Some(PacketSample {
        protocol,
        src: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(src)), sport),
        dst: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(dst)), dport),
        wire_bytes,
    })
}

/// Source/dest ports — the first four bytes of both TCP and UDP headers, the
/// only L4 bytes this module ever reads.
fn ports(l4: &[u8]) -> Option<(u16, u16)> {
    if l4.len() < 4 {
        return None;
    }
    Some((
        u16::from_be_bytes([l4[0], l4[1]]),
        u16::from_be_bytes([l4[2], l4[3]]),
    ))
}

/// Orient a sample as (local, remote) using the capture interface's own
/// addresses. `None` when neither end is ours — forwarded/multicast noise a
/// promiscuous capture can see but the connection table never would.
pub fn orient(
    sample: &PacketSample,
    local_ips: &HashSet<IpAddr>,
) -> Option<(SocketAddr, SocketAddr)> {
    if local_ips.contains(&sample.src.ip()) {
        Some((sample.src, sample.dst))
    } else if local_ips.contains(&sample.dst.ip()) {
        Some((sample.dst, sample.src))
    } else {
        None
    }
}

/// Aggregated traffic for one conversation since the last drain — what the
/// engine merges into its poll (byte-driven activity; flows the table missed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowTraffic {
    pub protocol: L4Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub packets: u64,
    pub bytes: u64,
}

/// The packet-observation seam. The engine only ever calls `drain`, so tests
/// drive the merge logic with a scripted observer and no capture library.
pub trait PacketObserve: Send {
    /// Take everything accumulated since the last call.
    fn drain(&mut self) -> Vec<FlowTraffic>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet II + IPv4 + TCP, `total` bytes on the wire.
    fn eth_ipv4_tcp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08; // ethertype IPv4
        f[13] = 0x00;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // v4, IHL 5
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&[0u8; 16]); // rest of a minimal TCP header
        f
    }

    #[test]
    fn parses_ethernet_ipv4_tcp() {
        let frame = eth_ipv4_tcp([10, 0, 0, 2], 50000, [1, 1, 1, 1], 443);
        let s = parse(LinkKind::Ethernet, &frame, 1234).unwrap();
        assert_eq!(s.protocol, L4Proto::Tcp);
        assert_eq!(s.src, "10.0.0.2:50000".parse().unwrap());
        assert_eq!(s.dst, "1.1.1.1:443".parse().unwrap());
        assert_eq!(s.wire_bytes, 1234);
    }

    #[test]
    fn parses_vlan_tagged_frame() {
        let inner = eth_ipv4_tcp([10, 0, 0, 2], 50000, [1, 1, 1, 1], 443);
        let mut frame = inner[..12].to_vec();
        frame.extend_from_slice(&[0x81, 0x00, 0x00, 0x2a]); // 802.1Q tag, VID 42
        frame.extend_from_slice(&inner[12..]); // real ethertype + payload
        assert!(parse(LinkKind::Ethernet, &frame, 64).is_some());
    }

    #[test]
    fn parses_ipv6_udp_over_raw() {
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60; // v6
        ip[6] = 17; // UDP
        ip[8..24].copy_from_slice(&"2606:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        ip[24..40].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        ip.extend_from_slice(&53u16.to_be_bytes());
        ip.extend_from_slice(&51000u16.to_be_bytes());
        ip.extend_from_slice(&[0u8; 4]);
        let s = parse(LinkKind::Raw, &ip, 90).unwrap();
        assert_eq!(s.protocol, L4Proto::Udp);
        assert_eq!(s.src.port(), 53);
        assert_eq!(s.dst.port(), 51000);
    }

    #[test]
    fn skips_arp_fragments_and_truncated() {
        // ARP ethertype.
        let mut arp = vec![0u8; 40];
        arp[12] = 0x08;
        arp[13] = 0x06;
        assert!(parse(LinkKind::Ethernet, &arp, 40).is_none());

        // Non-first IPv4 fragment: ports unreadable.
        let mut frag = eth_ipv4_tcp([10, 0, 0, 2], 50000, [1, 1, 1, 1], 443);
        frag[14 + 7] = 0x10; // fragment offset != 0
        assert!(parse(LinkKind::Ethernet, &frag, 64).is_none());

        // Truncated before the ports.
        let whole = eth_ipv4_tcp([10, 0, 0, 2], 50000, [1, 1, 1, 1], 443);
        assert!(parse(LinkKind::Ethernet, &whole[..36], 64).is_none());
    }

    #[test]
    fn orients_by_the_local_address_set() {
        let s = PacketSample {
            protocol: L4Proto::Tcp,
            src: "1.1.1.1:443".parse().unwrap(),
            dst: "10.0.0.2:50000".parse().unwrap(),
            wire_bytes: 100,
        };
        let locals: HashSet<IpAddr> = ["10.0.0.2".parse().unwrap()].into();
        // Inbound packet: the local end is the destination.
        let (local, remote) = orient(&s, &locals).unwrap();
        assert_eq!(local, "10.0.0.2:50000".parse().unwrap());
        assert_eq!(remote, "1.1.1.1:443".parse().unwrap());
        // Neither end local → transit noise, dropped.
        let neither: HashSet<IpAddr> = ["192.168.9.9".parse().unwrap()].into();
        assert!(orient(&s, &neither).is_none());
    }
}
