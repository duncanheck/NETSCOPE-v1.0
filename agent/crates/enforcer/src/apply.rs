//! The mechanism that actually edits the firewall — isolated behind a trait so the
//! enforcer's logic (auth, the never-block floor, bookkeeping) is testable without
//! privilege, and so the kernel write lives in exactly one small, reviewable place.
//!
//! The namespace matches the E3 generator exactly (`inet netscope`, sets `blocked4`
//! / `blocked6`, an `output` hook dropping `daddr @blocked*`), so the enforcer and
//! the hand-applied generator describe the *same* structure — one mental model.

use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

/// What the enforcer needs from a firewall backend. Errors are strings (surfaced to
/// the agent and the audit log); the trait is intentionally minimal.
pub trait Applier: Send + Sync {
    /// Create the table/sets/chain if absent — idempotent, preserves membership.
    fn ensure(&self) -> Result<(), String>;
    /// Add these addresses to the block set.
    fn add(&self, ips: &[IpAddr]) -> Result<(), String>;
    /// Remove these addresses from the block set.
    fn remove(&self, ips: &[IpAddr]) -> Result<(), String>;
    /// Tear the whole table down (removes every block at once).
    fn clear(&self) -> Result<(), String>;
    /// Read back what's *actually* blocked right now, straight from the OS
    /// firewall — not a cached/in-memory belief. This is the live half of
    /// `Verify`: it's how a drift (rules edited or wiped outside the
    /// enforcer) gets caught instead of silently trusted.
    fn verify(&self) -> Result<Vec<IpAddr>, String>;
}

/// Lets the daemon pick a backend at runtime (real nft / validate-only / mock)
/// behind one type without making the whole enforcer generic at the call site.
impl Applier for Box<dyn Applier> {
    fn ensure(&self) -> Result<(), String> {
        (**self).ensure()
    }
    fn add(&self, ips: &[IpAddr]) -> Result<(), String> {
        (**self).add(ips)
    }
    fn remove(&self, ips: &[IpAddr]) -> Result<(), String> {
        (**self).remove(ips)
    }
    fn clear(&self) -> Result<(), String> {
        (**self).clear()
    }
    fn verify(&self) -> Result<Vec<IpAddr>, String> {
        (**self).verify()
    }
}

/// Split addresses into v4/v6 literal lists (as strings) for nft set elements.
fn split(ips: &[IpAddr]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        match ip {
            IpAddr::V4(a) => v4.push(a.to_string()),
            IpAddr::V6(a) => v6.push(a.to_string()),
        }
    }
    (v4, v6)
}

/// The idempotent structure script: table + both interval sets + the output chain
/// whose rules drop traffic to either set. `add` is create-if-absent in nft, and
/// flushing only the chain re-points the rules without disturbing set membership.
pub fn ensure_script() -> String {
    "\
add table inet netscope
add set inet netscope blocked4 { type ipv4_addr; flags interval; }
add set inet netscope blocked6 { type ipv6_addr; flags interval; }
add chain inet netscope output { type filter hook output priority 0; policy accept; }
flush chain inet netscope output
add rule inet netscope output ip daddr @blocked4 drop
add rule inet netscope output ip6 daddr @blocked6 drop
"
    .to_string()
}

/// The `add element` script for the given addresses (empty if none of that family).
pub fn add_script(ips: &[IpAddr]) -> String {
    element_script("add", ips)
}

/// The `delete element` script for the given addresses.
pub fn remove_script(ips: &[IpAddr]) -> String {
    element_script("delete", ips)
}

/// Removing the whole table is the cleanest "unblock everything".
pub fn clear_script() -> String {
    "delete table inet netscope\n".to_string()
}

fn element_script(verb: &str, ips: &[IpAddr]) -> String {
    let (v4, v6) = split(ips);
    let mut s = String::new();
    if !v4.is_empty() {
        s.push_str(&format!(
            "{verb} element inet netscope blocked4 {{ {} }}\n",
            v4.join(", ")
        ));
    }
    if !v6.is_empty() {
        s.push_str(&format!(
            "{verb} element inet netscope blocked6 {{ {} }}\n",
            v6.join(", ")
        ));
    }
    s
}

/// The production backend: drives the real `nft` binary, feeding each script on
/// stdin (`nft -f -`) so there is no shell and no argument quoting to get wrong.
/// Only validated `IpAddr` values ever reach here, so the scripts are numeric by
/// construction (the same injection posture as the E3 generator).
pub struct NftApplier {
    /// When true, run `nft -c -f -` (parse/validate only, no privilege, no change) —
    /// used to verify script syntax in tests and on hosts without CAP_NET_ADMIN.
    check_only: bool,
}

impl NftApplier {
    pub fn new() -> Self {
        NftApplier { check_only: false }
    }
    pub fn checking() -> Self {
        NftApplier { check_only: true }
    }

    fn run(&self, script: &str) -> Result<(), String> {
        use std::io::Write;
        if script.trim().is_empty() {
            return Ok(());
        }
        let mut cmd = Command::new("nft");
        if self.check_only {
            cmd.arg("-c");
        }
        cmd.args(["-f", "-"]);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("spawning nft: {e}"))?;
        child
            .stdin
            .take()
            .ok_or("nft stdin unavailable")?
            .write_all(script.as_bytes())
            .map_err(|e| format!("writing to nft: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("waiting on nft: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "nft exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

impl Default for NftApplier {
    fn default() -> Self {
        Self::new()
    }
}

impl Applier for NftApplier {
    fn ensure(&self) -> Result<(), String> {
        self.run(&ensure_script())
    }
    fn add(&self, ips: &[IpAddr]) -> Result<(), String> {
        self.run(&add_script(ips))
    }
    fn remove(&self, ips: &[IpAddr]) -> Result<(), String> {
        self.run(&remove_script(ips))
    }
    fn clear(&self) -> Result<(), String> {
        // `delete table` errors if it's already gone; treat that as success.
        match self.run(&clear_script()) {
            Ok(()) => Ok(()),
            Err(e) if e.contains("No such file") || e.contains("does not exist") => Ok(()),
            Err(e) => Err(e),
        }
    }
    fn verify(&self) -> Result<Vec<IpAddr>, String> {
        // `-c` (check-only) mode never actually created a table to read, so there's
        // nothing live to verify — report empty rather than erroring, consistent
        // with how `checking()` mode has no real state anywhere else.
        if self.check_only {
            return Ok(Vec::new());
        }
        let mut all = read_live_set("blocked4")?;
        all.extend(read_live_set("blocked6")?);
        Ok(all)
    }
}

/// Read the *live* membership of one of our sets straight from the kernel via
/// `nft -j list set` (JSON output), independent of anything the enforcer has
/// cached in memory. A set/table that doesn't exist yet (never applied, or torn
/// down by `clear`) reads as empty, not an error — the same "no such file" case
/// `NftApplier::clear` already treats as a success.
fn read_live_set(set_name: &str) -> Result<Vec<IpAddr>, String> {
    let out = Command::new("nft")
        .args(["-j", "list", "set", "inet", "netscope", set_name])
        .output()
        .map_err(|e| format!("spawning nft: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("No such file") || stderr.contains("does not exist") {
            return Ok(Vec::new());
        }
        return Err(format!("nft exited {}: {}", out.status, stderr.trim()));
    }
    parse_set_json(&out.stdout)
}

/// Pull the `elem` array out of `nft -j list set`'s output and parse each entry
/// as an address. Our own writes (`element_script`) only ever add bare literals
/// (auto /32 or /128), which nft reports back as plain address strings — e.g.
/// `{"set": {..., "elem": ["1.2.3.4", "2001:db8::1"]}}`, verified against a real
/// `nft` binary. An empty/absent `elem` (nothing blocked) parses to `[]`. Entries
/// that aren't a bare address (a genuine CIDR range, which this applier never
/// creates) are skipped rather than failing the whole read.
fn parse_set_json(bytes: &[u8]) -> Result<Vec<IpAddr>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("parsing nft json: {e}"))?;
    let elems = v["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .find_map(|entry| entry.get("set"))
        .and_then(|set| set.get("elem"))
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(elems
        .into_iter()
        .filter_map(|e| e.as_str().and_then(|s| s.parse::<IpAddr>().ok()))
        .collect())
}

/// An in-memory applier for tests: records membership without touching the kernel.
#[derive(Default)]
pub struct MockApplier {
    pub ensured: Mutex<bool>,
    pub set: Mutex<std::collections::BTreeSet<IpAddr>>,
}

impl Applier for MockApplier {
    fn ensure(&self) -> Result<(), String> {
        *self.ensured.lock().unwrap() = true;
        Ok(())
    }
    fn add(&self, ips: &[IpAddr]) -> Result<(), String> {
        let mut s = self.set.lock().unwrap();
        s.extend(ips.iter().copied());
        Ok(())
    }
    fn remove(&self, ips: &[IpAddr]) -> Result<(), String> {
        let mut s = self.set.lock().unwrap();
        for ip in ips {
            s.remove(ip);
        }
        Ok(())
    }
    fn clear(&self) -> Result<(), String> {
        self.set.lock().unwrap().clear();
        Ok(())
    }
    fn verify(&self) -> Result<Vec<IpAddr>, String> {
        Ok(self.set.lock().unwrap().iter().copied().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn element_scripts_split_by_family_and_skip_empty() {
        let ips: Vec<IpAddr> = vec![
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ];
        let add = add_script(&ips);
        assert!(add.contains("add element inet netscope blocked4 { 1.2.3.4, 5.6.7.8 }"));
        assert!(add.contains("add element inet netscope blocked6 { 2001:db8::1 }"));

        // v4-only input emits no v6 line.
        let only4 = add_script(&["9.9.9.9".parse().unwrap()]);
        assert!(only4.contains("blocked4 { 9.9.9.9 }"));
        assert!(!only4.contains("blocked6"));

        let rm = remove_script(&["1.2.3.4".parse().unwrap()]);
        assert!(rm.starts_with("delete element inet netscope blocked4 { 1.2.3.4 }"));
    }

    #[test]
    fn mock_tracks_membership() {
        let m = MockApplier::default();
        m.ensure().unwrap();
        assert!(*m.ensured.lock().unwrap());
        m.add(&["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()])
            .unwrap();
        m.remove(&["1.1.1.1".parse().unwrap()]).unwrap();
        let set = m.set.lock().unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&"8.8.8.8".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn mock_verify_reflects_current_set() {
        let m = MockApplier::default();
        m.add(&["1.1.1.1".parse().unwrap()]).unwrap();
        assert_eq!(m.verify().unwrap(), vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    }

    // Fixtures captured from a real `nft -j list set` run (see the enforcer's
    // apply_windows.rs-sibling verification notes) — pinning the exact shape nft
    // emits for a set created by `ensure_script`/populated by `element_script`.
    #[test]
    fn parses_nft_json_elements() {
        let populated = br#"{"nftables": [{"metainfo": {"version": "1.0.9"}}, {"set": {"family": "inet", "name": "blocked4", "table": "netscope", "type": "ipv4_addr", "handle": 1, "flags": ["interval"], "elem": ["1.2.3.4", "5.6.7.8"]}}]}"#;
        let ips = parse_set_json(populated).unwrap();
        assert_eq!(
            ips,
            vec!["1.2.3.4".parse::<IpAddr>().unwrap(), "5.6.7.8".parse().unwrap()]
        );
    }

    #[test]
    fn parses_nft_json_empty_set_with_no_elem_key() {
        // An emptied set has no `elem` key at all, not `"elem": []`.
        let empty = br#"{"nftables": [{"metainfo": {"version": "1.0.9"}}, {"set": {"family": "inet", "name": "blocked4", "table": "netscope", "handle": 1, "flags": ["interval"]}}]}"#;
        assert_eq!(parse_set_json(empty).unwrap(), Vec::<IpAddr>::new());
    }

    #[test]
    fn checking_mode_verify_is_always_empty() {
        assert_eq!(NftApplier::checking().verify().unwrap(), Vec::<IpAddr>::new());
    }
}
