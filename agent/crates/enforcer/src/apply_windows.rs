//! The Windows firewall mechanism — the E4 applier for Windows Firewall.
//!
//! Same philosophy as the nftables applier: lean on the OS's own firewall, own a
//! single namespaced structure, and let only validated `IpAddr` values anywhere
//! near the command line. Here the structure is a set of outbound-block rules in
//! the firewall group **"NETSCOPE Warden"** (deliberately distinct from the E3
//! generator's hand-applied `"NETSCOPE"` group, so the two never clobber each
//! other), driven through PowerShell's NetSecurity cmdlets — the supported,
//! group-aware surface (`netsh advfirewall` cannot set a rule group on add).
//!
//! Unlike nft sets, firewall rules hold their address list in the rule itself, so
//! membership updates are a **resync**: the applier mirrors the full set in memory
//! and rewrites its group's rules on every change (delete group → re-add chunked
//! rules). Changes are rare and small, so the cost is irrelevant; the win is that
//! the rewrite is idempotent and self-healing.
//!
//! Injection posture, same as everywhere else in the Warden: rule names and the
//! group are compile-time constants; the only interpolated values are
//! `IpAddr::to_string()` outputs (digits, dots, hex, colons — nothing a
//! single-quoted PowerShell string could be escaped out of).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

use crate::apply::Applier;

/// The firewall group every rule lives in — the namespace, and the one-line
/// teardown selector (`Remove-NetFirewallRule -Group 'NETSCOPE Warden'`).
pub const GROUP: &str = "NETSCOPE Warden";

/// Addresses per rule. A rule's RemoteAddress list has practical command-line
/// limits; chunking keeps each command far under them.
const CHUNK: usize = 200;

/// The production Windows backend: rewrites the "NETSCOPE Warden" firewall group
/// through PowerShell NetSecurity cmdlets (`New-NetFirewallRule` /
/// `Remove-NetFirewallRule`). Requires elevation (the service runs as LocalSystem);
/// `checking()` appends `-WhatIf` so the whole path can be exercised unprivileged.
pub struct WfwApplier {
    /// When true, cmdlets run with `-WhatIf`: full parameter validation, no change,
    /// no privilege needed — the smoke-test mode, mirroring `NftApplier::checking()`.
    check_only: bool,
    /// The authoritative mirror of the block set, resynced into the firewall on
    /// every change.
    mirror: Mutex<BTreeSet<IpAddr>>,
}

impl WfwApplier {
    pub fn new() -> Self {
        WfwApplier {
            check_only: false,
            mirror: Mutex::new(BTreeSet::new()),
        }
    }
    pub fn checking() -> Self {
        WfwApplier {
            check_only: true,
            mirror: Mutex::new(BTreeSet::new()),
        }
    }

    /// Run one PowerShell script (no shell string-splitting — the script is a
    /// single argv entry) and hand back the raw process output.
    fn run_ps(&self, script: &str) -> Result<std::process::Output, String> {
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .output()
            .map_err(|e| format!("spawning powershell: {e}"))
    }

    /// Run a script for effect, surfacing stderr on failure.
    fn ps(&self, script: &str) -> Result<(), String> {
        let out = self.run_ps(script)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!("powershell exited {}: {}", out.status, ps_error(&out)))
        }
    }

    /// Run a script and return its stdout, for `verify()` — a live read, not a
    /// state-changing command.
    fn ps_query(&self, script: &str) -> Result<String, String> {
        let out = self.run_ps(script)?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!("powershell exited {}: {}", out.status, ps_error(&out)))
        }
    }

    /// The delete-group + re-add script for the given full membership. Written as
    /// one script so a resync is a single PowerShell invocation.
    fn resync_script(&self, ips: &BTreeSet<IpAddr>) -> String {
        let what_if = if self.check_only { " -WhatIf" } else { "" };
        let mut s = String::from("$ErrorActionPreference = 'Stop'\n");
        // Remove everything in our group. "No rules in the group" is the normal
        // empty case, not an error — but a suppressed non-terminating error still
        // flips `$?`, which `powershell -Command` turns into exit 1, so collect
        // first and only pipe to Remove when there's something to remove. Real
        // failures throw (ErrorActionPreference=Stop) and exit non-zero.
        s.push_str(&format!(
            "$rules = @(Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue)\n\
             if ($rules.Count -gt 0) {{ $rules | Remove-NetFirewallRule{what_if} }}\n"
        ));
        let all: Vec<String> = ips.iter().map(|ip| format!("'{ip}'")).collect();
        for (i, chunk) in all.chunks(CHUNK).enumerate() {
            s.push_str(&format!(
                "New-NetFirewallRule -DisplayName '{GROUP} block {n}' -Group '{GROUP}' \
                 -Direction Outbound -Action Block -Enabled True -Profile Any \
                 -RemoteAddress {list}{what_if} | Out-Null\n",
                n = i + 1,
                list = chunk.join(",")
            ));
        }
        // Reached only if nothing threw; makes success unambiguous to the caller.
        s.push_str("exit 0\n");
        s
    }

    fn resync(&self, ips: &BTreeSet<IpAddr>) -> Result<(), String> {
        self.ps(&self.resync_script(ips))
    }

    /// The read-only script for `verify()`: list every remote address bound to a
    /// rule in our group, straight from Windows Firewall — not the in-memory
    /// `mirror`. One address per line of stdout (PowerShell's default pipeline
    /// formatting for a `string[]` property), which `verify()` parses.
    fn verify_script(&self) -> String {
        format!(
            "$ErrorActionPreference = 'Stop'\n\
             $rules = @(Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue)\n\
             if ($rules.Count -gt 0) {{ $rules | Get-NetFirewallAddressFilter | \
             Select-Object -ExpandProperty RemoteAddress }}\n"
        )
    }
}

/// Parse `verify_script()`'s stdout (one address per line, plus PowerShell's own
/// blank-line formatting noise, and `Any` for a rule with no explicit remote
/// filter) into the addresses actually present. Kept separate from `ps_query` so
/// the parsing itself is unit-testable without a real PowerShell/Windows Firewall
/// round trip.
fn parse_remote_addresses(text: &str) -> Vec<IpAddr> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.eq_ignore_ascii_case("any"))
        .filter_map(|l| l.parse::<IpAddr>().ok())
        .collect()
}

/// Extract the most useful error text from a failed PowerShell run — stderr when
/// present, falling back to stdout (some cmdlet errors land there instead).
fn ps_error(out: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&out.stderr);
    let err = err.trim();
    if err.is_empty() {
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    } else {
        err.to_string()
    }
}

impl Default for WfwApplier {
    fn default() -> Self {
        Self::new()
    }
}

impl Applier for WfwApplier {
    /// Start clean: remove any rules a previous run left in our group, so the
    /// in-memory mirror and the firewall always agree. (Windows Firewall rules
    /// persist across reboots — without this, a crash could leave orphaned blocks
    /// no UI can list or undo.)
    fn ensure(&self) -> Result<(), String> {
        let mirror = self.mirror.lock().unwrap();
        self.resync(&mirror)
    }

    fn add(&self, ips: &[IpAddr]) -> Result<(), String> {
        let mut mirror = self.mirror.lock().unwrap();
        let before: BTreeSet<IpAddr> = mirror.clone();
        mirror.extend(ips.iter().copied());
        if let Err(e) = self.resync(&mirror) {
            *mirror = before; // keep the mirror honest on failure
            return Err(e);
        }
        Ok(())
    }

    fn remove(&self, ips: &[IpAddr]) -> Result<(), String> {
        let mut mirror = self.mirror.lock().unwrap();
        let before: BTreeSet<IpAddr> = mirror.clone();
        for ip in ips {
            mirror.remove(ip);
        }
        if let Err(e) = self.resync(&mirror) {
            *mirror = before;
            return Err(e);
        }
        Ok(())
    }

    fn clear(&self) -> Result<(), String> {
        let mut mirror = self.mirror.lock().unwrap();
        mirror.clear();
        self.resync(&mirror)
    }

    /// Read back what Windows Firewall itself reports for our group — independent
    /// of `mirror`, which is only ever what *we last told it to be*, not proof it
    /// stuck (a failed resync could leave `mirror` ahead of reality; an admin or
    /// another tool could edit the group directly).
    fn verify(&self) -> Result<Vec<IpAddr>, String> {
        if self.check_only {
            // `-WhatIf` mode never wrote anything real; there's nothing live to
            // read back, matching `NftApplier::verify`'s checking-mode case.
            return Ok(Vec::new());
        }
        let out = self.ps_query(&self.verify_script())?;
        Ok(parse_remote_addresses(&out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn resync_script_is_numeric_only_and_chunked() {
        let a = WfwApplier::new();
        let mut set = BTreeSet::new();
        set.insert(ip("8.8.8.8"));
        set.insert(ip("2001:db8::1"));
        let s = a.resync_script(&set);
        assert!(s.contains("Remove-NetFirewallRule"));
        assert!(s.contains("New-NetFirewallRule -DisplayName 'NETSCOPE Warden block 1'"));
        // BTreeSet<IpAddr> orders v4 before v6.
        assert!(s.contains("'8.8.8.8','2001:db8::1'"));
        assert!(!s.contains("-WhatIf"));

        // > CHUNK addresses split into multiple rules.
        let mut big = BTreeSet::new();
        for i in 0..(CHUNK + 1) {
            big.insert(ip(&format!("10.{}.{}.1", i / 256, i % 256)));
        }
        let s = a.resync_script(&big);
        assert!(s.contains("block 1"));
        assert!(s.contains("block 2"));
    }

    #[test]
    fn checking_mode_appends_whatif() {
        let a = WfwApplier::checking();
        let mut set = BTreeSet::new();
        set.insert(ip("9.9.9.9"));
        let s = a.resync_script(&set);
        assert!(s.contains("Remove-NetFirewallRule -WhatIf"));
        assert!(s.contains("-RemoteAddress '9.9.9.9' -WhatIf"));
    }

    #[test]
    fn empty_set_only_clears() {
        let a = WfwApplier::new();
        let s = a.resync_script(&BTreeSet::new());
        assert!(s.contains("Remove-NetFirewallRule"));
        assert!(!s.contains("New-NetFirewallRule"));
    }

    #[test]
    fn verify_script_is_read_only() {
        let a = WfwApplier::new();
        let s = a.verify_script();
        assert!(s.contains("Get-NetFirewallRule -Group 'NETSCOPE Warden'"));
        assert!(s.contains("Get-NetFirewallAddressFilter"));
        // Never mutates the firewall — no New/Remove-NetFirewallRule here.
        assert!(!s.contains("New-NetFirewallRule"));
        assert!(!s.contains("Remove-NetFirewallRule"));
    }

    #[test]
    fn checking_mode_verify_is_always_empty() {
        // -WhatIf never wrote anything real, so there's nothing to read back —
        // and critically, this must not shell out to a nonexistent
        // powershell.exe on a non-Windows test host.
        assert_eq!(WfwApplier::checking().verify().unwrap(), Vec::<IpAddr>::new());
    }

    #[test]
    fn parses_remote_addresses_skips_blank_and_any() {
        let text = "8.8.8.8\n\nAny\n2001:db8::1\n  9.9.9.9  \n";
        assert_eq!(
            parse_remote_addresses(text),
            vec![ip("8.8.8.8"), ip("2001:db8::1"), ip("9.9.9.9")]
        );
    }

    #[test]
    fn parses_remote_addresses_empty_output() {
        assert_eq!(parse_remote_addresses(""), Vec::<IpAddr>::new());
    }
}
