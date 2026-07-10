//! Windows connection-table source: reads the TCP tables via `GetExtendedTcpTable`
//! (the `OWNER_PID` variants, so every row already names its process), and resolves
//! each owning PID to a name/path through the process APIs. The Windows half of A2,
//! behind the same [`ConnectionSource`](super::ConnectionSource) as the Linux
//! procfs reader — the engine above the trait is unchanged.
//!
//! ## Two honest limitations (documented, not hidden)
//!
//! - **TCP only.** Windows' `MIB_UDPROW_OWNER_PID` carries *no remote address* (UDP
//!   is connectionless and the owner-PID table lists only local binds), so a UDP
//!   row can't be rendered as an outbound conversation. We therefore omit UDP on
//!   Windows; QUIC/HTTP-3 and DNS won't appear. (Linux's `/proc/net/udp` does carry
//!   the peer for `connect()`-ed sockets, which is why it captures some UDP.)
//! - **PID reuse** is handled the same way as on Linux: process identity is cached
//!   on `(pid, creation_time)` from `GetProcessTimes`, so a recycled PID re-resolves
//!   rather than inheriting a dead process's name.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use netscope_protocol::{L4Proto, ProcessInfo};

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, FALSE, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{ConnectionSource, RawConn, TcpState};

/// Windows TCP `ESTABLISHED` state code (`MIB_TCP_STATE_ESTAB`).
const MIB_TCP_STATE_ESTAB: u32 = 5;

pub struct IpHelperSource {
    /// Process identity cache, keyed on `(pid, creation_time)` to defeat PID reuse.
    proc_cache: HashMap<(u32, u64), ProcessInfo>,
}

impl IpHelperSource {
    pub fn new() -> Self {
        Self {
            proc_cache: HashMap::new(),
        }
    }
}

impl ConnectionSource for IpHelperSource {
    fn poll(&mut self) -> std::io::Result<Vec<RawConn>> {
        let mut rows = Vec::new();
        self.collect_tcp_v4(&mut rows);
        self.collect_tcp_v6(&mut rows);

        // Track the cache to the live PID set, as the Linux source does.
        let live: std::collections::HashSet<u32> = rows
            .iter()
            .filter_map(|r| r.process.as_ref().map(|p| p.pid))
            .collect();
        self.proc_cache.retain(|(pid, _), _| live.contains(pid));

        Ok(rows)
    }
}

impl IpHelperSource {
    fn collect_tcp_v4(&mut self, out: &mut Vec<RawConn>) {
        let Some(buf) = get_extended_tcp_table(AF_INET.0 as u32) else {
            return;
        };
        // SAFETY: on success the buffer begins with a MIB_TCPTABLE_OWNER_PID whose
        // `table` is `dwNumEntries` contiguous rows.
        unsafe {
            let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let n = (*table).dwNumEntries as usize;
            let rows = std::slice::from_raw_parts((*table).table.as_ptr(), n);
            for row in rows {
                out.push(self.tcp_v4_row(row));
            }
        }
    }

    fn collect_tcp_v6(&mut self, out: &mut Vec<RawConn>) {
        let Some(buf) = get_extended_tcp_table(AF_INET6.0 as u32) else {
            return;
        };
        // SAFETY: as above, for the IPv6 table shape.
        unsafe {
            let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
            let n = (*table).dwNumEntries as usize;
            let rows = std::slice::from_raw_parts((*table).table.as_ptr(), n);
            for row in rows {
                out.push(self.tcp_v6_row(row));
            }
        }
    }

    fn tcp_v4_row(&mut self, row: &MIB_TCPROW_OWNER_PID) -> RawConn {
        let local = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
            port_from_dword(row.dwLocalPort),
        );
        let remote = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes())),
            port_from_dword(row.dwRemotePort),
        );
        RawConn {
            protocol: L4Proto::Tcp,
            local,
            remote,
            tcp_state: Some(tcp_state(row.dwState)),
            process: self.resolve_process(row.dwOwningPid),
        }
    }

    fn tcp_v6_row(&mut self, row: &MIB_TCP6ROW_OWNER_PID) -> RawConn {
        let local = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
            port_from_dword(row.dwLocalPort),
        );
        let remote = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
            port_from_dword(row.dwRemotePort),
        );
        RawConn {
            protocol: L4Proto::Tcp,
            local,
            remote,
            tcp_state: Some(tcp_state(row.dwState)),
            process: self.resolve_process(row.dwOwningPid),
        }
    }

    /// Resolve a PID to its process info, cached on `(pid, creation_time)`. Any
    /// failure (PID 0, access denied for a protected/system process) yields `None`,
    /// which the UI renders as a protected process (PITFALLS A2).
    fn resolve_process(&mut self, pid: u32) -> Option<ProcessInfo> {
        if pid == 0 {
            return None; // System Idle / no owner
        }
        // SAFETY: a successful OpenProcess hands back a handle we always close.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid).ok()?;
            let result = self.resolve_with_handle(pid, handle);
            let _ = CloseHandle(handle);
            result
        }
    }

    /// # Safety
    /// `handle` must be a live process handle with query rights.
    unsafe fn resolve_with_handle(&mut self, pid: u32, handle: HANDLE) -> Option<ProcessInfo> {
        // Creation time → the PID-reuse-safe cache key.
        let mut creation = Default::default();
        let mut exit = Default::default();
        let mut kernel = Default::default();
        let mut user = Default::default();
        GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).ok()?;
        let start = filetime_to_u64(&creation);

        let key = (pid, start);
        if let Some(hit) = self.proc_cache.get(&key) {
            return Some(hit.clone());
        }

        // Full image path; QueryFullProcessImageNameW writes `size` chars.
        let mut buf = [0u16; 260];
        let mut size = buf.len() as u32;
        let path = if QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
        {
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        } else {
            None
        };

        let name = path
            .as_deref()
            .and_then(file_name)
            .unwrap_or_else(|| format!("pid {pid}"));

        let info = ProcessInfo { pid, name, path };
        self.proc_cache.insert(key, info.clone());
        Some(info)
    }
}

/// Call `GetExtendedTcpTable` with the two-call size pattern, returning the raw
/// table buffer (or `None` on error / empty).
///
/// The buffer is a `Vec<u32>`, not `Vec<u8>`, on purpose: the caller reinterprets
/// it as a `MIB_*TABLE_OWNER_PID` (4-byte aligned, all `u32`/`[u8;16]` fields), and
/// reading those through a `u8` (align-1) allocation would be undefined behaviour.
/// A `Vec<u32>` guarantees 4-byte alignment for the same bytes.
fn get_extended_tcp_table(af: u32) -> Option<Vec<u32>> {
    let mut size: u32 = 0;
    // First call: ask for the required size (in bytes).
    // SAFETY: a null table pointer with a size-out is the documented sizing call.
    let err =
        unsafe { GetExtendedTcpTable(None, &mut size, FALSE, af, TCP_TABLE_OWNER_PID_ALL, 0) };
    if err != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
        return None;
    }

    // Round the byte count up to whole u32s; the extra ≤3 bytes are harmless slack.
    let mut buf = vec![0u32; (size as usize).div_ceil(4)];
    // SAFETY: buffer holds ≥ `size` bytes, matching what the sizing call requested.
    let err = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            FALSE,
            af,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if err != 0 {
        return None;
    }
    Some(buf)
}

/// The low word of a `dw*Port` holds the port in network byte order; `from_be`
/// converts it to host order (`ntohs`).
fn port_from_dword(dw: u32) -> u16 {
    u16::from_be((dw & 0xFFFF) as u16)
}

fn tcp_state(state: u32) -> TcpState {
    if state == MIB_TCP_STATE_ESTAB {
        TcpState::Established
    } else {
        TcpState::Other
    }
}

/// Combine a `FILETIME`'s two 32-bit halves into the 64-bit tick count.
fn filetime_to_u64(ft: &windows::Win32::Foundation::FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

/// File name (with extension) from a Windows path, e.g. `C:\...\chrome.exe`.
fn file_name(path: &str) -> Option<String> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_byte_order() {
        // 0x01BB in network order is 443; stored in the low word as 0xBB01 on LE.
        assert_eq!(port_from_dword(0xBB01), 443);
    }

    #[test]
    fn file_name_from_windows_path() {
        assert_eq!(
            file_name(r"C:\Program Files\chrome.exe").as_deref(),
            Some("chrome.exe")
        );
        assert_eq!(file_name("svchost.exe").as_deref(), Some("svchost.exe"));
        assert_eq!(file_name(r"C:\dir\").as_deref(), None);
    }
}
