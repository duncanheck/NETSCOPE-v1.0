//! Linux connection-table source: reads `/proc/net/{tcp,tcp6,udp,udp6}`,
//! attributes each socket to its owning process via the socket inode, and caches
//! process identity on `(pid, start_time)` so a recycled pid can't inherit a dead
//! process's name (PITFALLS A2).
//!
//! This is the OS-API half of A2. The Windows port reads the same shape out of
//! `GetExtendedTcpTable`/`GetExtendedUdpTable` and slots in behind
//! [`ConnectionSource`](super::ConnectionSource) unchanged.
//!
//! ### How attribution works
//!
//! `/proc/net/tcp` gives each socket an inode but not a pid. The pid lives on the
//! other side: a process holds the socket as an open fd, and `/proc/<pid>/fd/<n>`
//! is a symlink reading `socket:[<inode>]`. So once per poll we sweep `/proc/*/fd`
//! to build an `inode → pid` map, then join it against the socket table. Sockets
//! owned by processes we can't read (other users, when unprivileged) simply don't
//! appear in the map and resolve to `process: None` — the protected-process path.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use netscope_protocol::{L4Proto, ProcessInfo};

use super::{ConnectionSource, RawConn, TcpState};

pub struct ProcfsSource {
    /// Process identity cache, keyed on `(pid, start_time)` to defeat PID reuse.
    proc_cache: HashMap<(u32, u64), ProcessInfo>,
}

impl ProcfsSource {
    pub fn new() -> Self {
        Self {
            proc_cache: HashMap::new(),
        }
    }
}

impl ConnectionSource for ProcfsSource {
    fn poll(&mut self) -> std::io::Result<Vec<RawConn>> {
        let inode_to_pid = build_inode_pid_map();

        let mut rows = Vec::new();
        // tcp/tcp6 carry connection state; udp/udp6 do not.
        parse_net_table(
            "/proc/net/tcp",
            L4Proto::Tcp,
            false,
            &inode_to_pid,
            self,
            &mut rows,
        );
        parse_net_table(
            "/proc/net/tcp6",
            L4Proto::Tcp,
            true,
            &inode_to_pid,
            self,
            &mut rows,
        );
        parse_net_table(
            "/proc/net/udp",
            L4Proto::Udp,
            false,
            &inode_to_pid,
            self,
            &mut rows,
        );
        parse_net_table(
            "/proc/net/udp6",
            L4Proto::Udp,
            true,
            &inode_to_pid,
            self,
            &mut rows,
        );

        // Drop cache entries for processes that no longer own any live socket, so
        // the cache tracks the connection set rather than growing without bound.
        let live: std::collections::HashSet<u32> = rows
            .iter()
            .filter_map(|r| r.process.as_ref().map(|p| p.pid))
            .collect();
        self.proc_cache.retain(|(pid, _), _| live.contains(pid));

        Ok(rows)
    }
}

/// Parse one `/proc/net/*` table into [`RawConn`] rows, appending to `out`. A
/// malformed line is skipped rather than failing the whole poll — the table is
/// kernel-formatted but we stay defensive.
fn parse_net_table(
    path: &str,
    protocol: L4Proto,
    v6: bool,
    inode_to_pid: &HashMap<u64, u32>,
    src: &mut ProcfsSource,
    out: &mut Vec<RawConn>,
) {
    let Ok(contents) = fs::read_to_string(path) else {
        return; // table absent (e.g. IPv6 disabled) — not an error
    };

    for line in contents.lines().skip(1) {
        let mut f = line.split_whitespace();
        // Columns: sl local_address rem_address st ... uid ... inode ...
        let Some(_sl) = f.next() else { continue };
        let Some(local) = f.next().and_then(|s| parse_addr(s, v6)) else {
            continue;
        };
        let Some(remote) = f.next().and_then(|s| parse_addr(s, v6)) else {
            continue;
        };
        let Some(st_hex) = f.next() else { continue };
        // tx/rx queue, tr, tm->when, retrnsmt, uid, timeout, then inode.
        let inode = f.clone().nth(5).and_then(|s| s.parse::<u64>().ok());

        let tcp_state = match protocol {
            L4Proto::Tcp => Some(parse_tcp_state(st_hex)),
            L4Proto::Udp => None,
        };

        let process = inode
            .and_then(|ino| inode_to_pid.get(&ino).copied())
            .and_then(|pid| src.resolve_process(pid));

        out.push(RawConn {
            protocol,
            local,
            remote,
            tcp_state,
            process,
        });
    }
}

impl ProcfsSource {
    /// Resolve a pid to its process info, cached on `(pid, start_time)`. If the
    /// pid is alive but its start_time differs from a cached entry, the pid was
    /// reused and the stale entry is ignored.
    fn resolve_process(&mut self, pid: u32) -> Option<ProcessInfo> {
        let start_time = read_start_time(pid)?;
        let key = (pid, start_time);
        if let Some(hit) = self.proc_cache.get(&key) {
            return Some(hit.clone());
        }
        let name = fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim_end().to_string())
            .unwrap_or_else(|| format!("pid {pid}"));
        // /proc/<pid>/exe is a symlink; readlink fails (EACCES) for processes we
        // can't introspect — path stays None, which the UI renders gracefully.
        let path = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        let info = ProcessInfo { pid, name, path };
        self.proc_cache.insert(key, info.clone());
        Some(info)
    }
}

/// Read field 22 (`starttime`, clock ticks since boot) from `/proc/<pid>/stat`.
/// The process name in field 2 is parenthesized and may contain spaces, so we
/// split after the closing paren rather than on whitespace from the front.
fn read_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1; // everything past "(comm)"
                                               // Fields from here are: state(3) ppid(4) ... starttime(22). After the paren
                                               // we're at field 3, so starttime is index 22 - 3 = 19 in this slice.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// Sweep `/proc/<pid>/fd/*` for socket symlinks, building `inode → pid`. fds we
/// can't read are skipped silently (unprivileged: only our own processes appear).
fn build_inode_pid_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue; // non-numeric /proc entry
        };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue; // process gone or not ours
        };
        for fd in fds.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                if let Some(inode) = parse_socket_inode(&target.to_string_lossy()) {
                    map.insert(inode, pid);
                }
            }
        }
    }
    map
}

/// `"socket:[12345]"` → `12345`.
fn parse_socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Parse a `/proc/net/*` address column (`HEXADDR:HEXPORT`) into a `SocketAddr`.
/// The address bytes are host-endian per 32-bit word: IPv4 is one little-endian
/// u32; IPv6 is four little-endian u32 words.
fn parse_addr(s: &str, v6: bool) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if v6 {
        if addr_hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for word in 0..4 {
            let raw = u32::from_str_radix(&addr_hex[word * 8..word * 8 + 8], 16).ok()?;
            bytes[word * 4..word * 4 + 4].copy_from_slice(&raw.to_le_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        let raw = u32::from_str_radix(addr_hex, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
    };
    Some(SocketAddr::new(ip, port))
}

/// Map the kernel's hex TCP state to the two buckets A2 distinguishes. `01` is
/// ESTABLISHED; everything else (handshake, wait, close) is "other".
fn parse_tcp_state(hex: &str) -> TcpState {
    match hex {
        "01" => TcpState::Established,
        _ => TcpState::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_address_column() {
        // 0100007F:ACAD → 127.0.0.1:44205 (little-endian u32).
        let a = parse_addr("0100007F:ACAD", false).unwrap();
        assert_eq!(a.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(a.port(), 0xACAD);
    }

    #[test]
    fn parses_ipv6_address_column() {
        // IPv6 loopback ::1 as four LE words, with port 0x01BB (443).
        let s = "00000000000000000000000001000000:01BB";
        let a = parse_addr(s, true).unwrap();
        assert_eq!(a.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(a.port(), 443);
    }

    #[test]
    fn extracts_socket_inode() {
        assert_eq!(parse_socket_inode("socket:[3082]"), Some(3082));
        assert_eq!(parse_socket_inode("anon_inode:[eventfd]"), None);
        assert_eq!(parse_socket_inode("/dev/null"), None);
    }

    #[test]
    fn maps_tcp_states() {
        assert_eq!(parse_tcp_state("01"), TcpState::Established);
        assert_eq!(parse_tcp_state("0A"), TcpState::Other); // LISTEN
        assert_eq!(parse_tcp_state("06"), TcpState::Other); // TIME_WAIT
    }

    /// Smoke test against the real procfs of the test process — never panics, and
    /// any row it does produce is internally consistent.
    #[test]
    fn polls_real_procfs_without_panicking() {
        let mut src = ProcfsSource::new();
        let rows = src.poll().expect("poll should not error");
        for r in &rows {
            if let Some(p) = &r.process {
                assert!(p.pid > 0);
            }
        }
    }
}
