//! # pcap — the libpcap/Npcap device glue (GROWTH G5)
//!
//! The platform half of the packet path: opens a capture device, runs a reader
//! thread, and aggregates parsed headers into per-conversation counters the
//! engine drains once per poll. All the parsing/orientation logic is in
//! [`super::packet`] (pure, tested everywhere); this file is only the device
//! lifecycle, and only compiles with `--features pcap` (libpcap on Unix, the
//! Npcap SDK + installed Npcap driver on Windows).
//!
//! ## The posture, stated plainly
//!
//! - **Opt-in twice**: compiled in by a cargo feature, enabled by
//!   `NETSCOPE_PCAP=1`. The default build and the default run are still the
//!   metadata-only polling path with its measured <1%-CPU budget.
//! - **Headers only, structurally**: snaplen 96 caps what the kernel hands us
//!   at link+IP+L4 headers; the parser never reads past the port words. Payload
//!   is not truncated away as a courtesy — it never reaches this process.
//! - **Aggregates only**: what crosses the thread boundary is per-5-tuple
//!   packet/byte counters, drained ~4×/s. No packet is stored, queued, or
//!   forwarded.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use netscope_protocol::L4Proto;

use super::packet::{orient, parse, FlowTraffic, LinkKind, PacketObserve};

/// Headers only: 14 (eth) + 4 (vlan) + 40 (ipv6) + enough L4 for the ports,
/// with margin. The kernel never hands us payload past this.
const SNAPLEN: i32 = 96;
/// Read timeout so the thread wakes to check the stop flag even on a quiet wire.
const READ_TIMEOUT_MS: i32 = 250;

type Key = (L4Proto, SocketAddr, SocketAddr);

pub struct PcapObserver {
    stats: Arc<Mutex<HashMap<Key, (u64, u64)>>>,
    stop: Arc<AtomicBool>,
}

impl PcapObserver {
    /// Open the capture device (`NETSCOPE_PCAP_DEVICE` overrides the default)
    /// and start the reader thread. Errors are strings meant for the System
    /// panel — "permission denied" here usually means missing CAP_NET_RAW/root
    /// (Linux) or a missing Npcap driver (Windows).
    pub fn start() -> Result<(Self, String), String> {
        let device = match std::env::var("NETSCOPE_PCAP_DEVICE") {
            Ok(name) if !name.trim().is_empty() => pcap::Device::list()
                .map_err(|e| format!("list devices: {e}"))?
                .into_iter()
                .find(|d| d.name == name.trim())
                .ok_or_else(|| format!("device {name} not found"))?,
            _ => pcap::Device::lookup()
                .map_err(|e| format!("device lookup: {e}"))?
                .ok_or("no capturable device found")?,
        };
        let name = device.name.clone();
        // The interface's own addresses orient each packet as local↔remote.
        let local_ips: HashSet<IpAddr> = device.addresses.iter().map(|a| a.addr).collect();
        if local_ips.is_empty() {
            return Err(format!("device {name} has no addresses to orient by"));
        }

        let mut cap = pcap::Capture::from_device(device)
            .map_err(|e| format!("open {name}: {e}"))?
            .snaplen(SNAPLEN)
            .timeout(READ_TIMEOUT_MS)
            .open()
            .map_err(|e| format!("activate {name}: {e}"))?;
        // L4 conversations only — the kernel filters before we ever copy.
        cap.filter("tcp or udp", true)
            .map_err(|e| format!("bpf filter: {e}"))?;
        let link = match cap.get_datalink().0 {
            1 => LinkKind::Ethernet,
            0 | 108 => LinkKind::Null,
            12 | 14 | 101 => LinkKind::Raw,
            other => return Err(format!("unsupported link type {other} on {name}")),
        };

        let stats: Arc<Mutex<HashMap<Key, (u64, u64)>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        {
            let stats = Arc::clone(&stats);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("netscope-pcap".into())
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        match cap.next_packet() {
                            Ok(pkt) => {
                                let Some(sample) = parse(link, pkt.data, u64::from(pkt.header.len))
                                else {
                                    continue;
                                };
                                let Some((local, remote)) = orient(&sample, &local_ips) else {
                                    continue;
                                };
                                let mut map = stats.lock().unwrap();
                                let e = map
                                    .entry((sample.protocol, local, remote))
                                    .or_insert((0, 0));
                                e.0 += 1;
                                e.1 += sample.wire_bytes;
                            }
                            Err(pcap::Error::TimeoutExpired) => continue,
                            Err(e) => {
                                tracing::warn!(error = %e, "packet capture stopped");
                                break;
                            }
                        }
                    }
                })
                .map_err(|e| format!("spawn reader: {e}"))?;
        }

        Ok((Self { stats, stop }, name))
    }
}

impl PacketObserve for PcapObserver {
    fn drain(&mut self) -> Vec<FlowTraffic> {
        let mut map = self.stats.lock().unwrap();
        map.drain()
            .map(
                |((protocol, local, remote), (packets, bytes))| FlowTraffic {
                    protocol,
                    local,
                    remote,
                    packets,
                    bytes,
                },
            )
            .collect()
    }
}

impl Drop for PcapObserver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
