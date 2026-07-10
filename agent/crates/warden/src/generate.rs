//! # E3 — the firewall generator
//!
//! Turn a policy's block targets ([`crate::Plan::targets`]) into an **OS-native,
//! namespaced, reversible** ruleset the user can read and apply by hand — zero
//! privilege, zero risk, and the literal "firewall generator" Track E promised.
//!
//! Three properties make this safe:
//!
//! - **No injection by construction.** Only addresses that *parse* as an IPv4/IPv6
//!   literal or CIDR reach the output. A hostname, a shell metacharacter, anything
//!   malformed — dropped. The firewall tool's own parser is the second check.
//! - **Namespaced.** Everything lives in its own `inet netscope` table / `netscope`
//!   pf anchor / `NETSCOPE` firewall group, so it never touches the user's existing
//!   rules, and teardown is a single command.
//! - **Outbound-only, atomically re-appliable.** Rules drop *outbound* traffic to
//!   the blocked set; re-running the file replaces the prior version cleanly.
//!
//! The [`is_protected`](crate::evaluate) floor already kept loopback / LAN / tailnet
//! out of `targets`, so the generated rules can't cut you off from your own network.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Which firewall backend to generate for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Firewall {
    /// Linux, modern (`nft -f`).
    Nftables,
    /// Windows (`netsh advfirewall`, elevated).
    Netsh,
    /// macOS / BSD (`pfctl` anchor).
    Pf,
}

impl Firewall {
    pub fn label(self) -> &'static str {
        match self {
            Firewall::Nftables => "Linux (nftables)",
            Firewall::Netsh => "Windows (netsh)",
            Firewall::Pf => "macOS (pf)",
        }
    }
    pub fn filename(self) -> &'static str {
        match self {
            Firewall::Nftables => "netscope-block.nft",
            Firewall::Netsh => "netscope-block.bat",
            Firewall::Pf => "netscope-block.pf",
        }
    }
}

/// Every backend, for a UI menu.
pub fn all_backends() -> [Firewall; 3] {
    [Firewall::Nftables, Firewall::Netsh, Firewall::Pf]
}

/// The backend matching the host the agent is running on — the sensible default.
pub fn default_backend() -> Firewall {
    if cfg!(target_os = "windows") {
        Firewall::Netsh
    } else if cfg!(target_os = "macos") {
        Firewall::Pf
    } else {
        Firewall::Nftables
    }
}

/// A generated ruleset: the rules text plus how to apply and remove it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeneratedRuleset {
    pub backend: Firewall,
    pub filename: String,
    pub apply: String,
    pub remove: String,
    /// How many of the requested targets were valid and included.
    pub target_count: usize,
    /// The ruleset text — only validated numeric addresses, never raw input.
    pub rules: String,
}

/// Generate a native ruleset that blocks outbound traffic to `targets` (IP literals
/// or CIDRs). Invalid entries are silently dropped — only parsed addresses appear.
pub fn generate(backend: Firewall, targets: &[String]) -> GeneratedRuleset {
    let (v4, v6) = split_valid(targets);
    let target_count = v4.len() + v6.len();
    let rules = match backend {
        Firewall::Nftables => nftables(&v4, &v6),
        Firewall::Netsh => netsh(&v4, &v6),
        Firewall::Pf => pf(&v4, &v6),
    };
    let (apply, remove) = hints(backend);
    GeneratedRuleset {
        backend,
        filename: backend.filename().to_string(),
        apply,
        remove,
        target_count,
        rules,
    }
}

fn hints(backend: Firewall) -> (String, String) {
    match backend {
        Firewall::Nftables => (
            "sudo nft -f netscope-block.nft".into(),
            "sudo nft delete table inet netscope".into(),
        ),
        Firewall::Netsh => (
            "run netscope-block.bat in an elevated Command Prompt".into(),
            r#"netsh advfirewall firewall delete rule name=all group="NETSCOPE""#.into(),
        ),
        Firewall::Pf => (
            "sudo pfctl -a netscope -f netscope-block.pf && sudo pfctl -e".into(),
            "sudo pfctl -a netscope -F all".into(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

fn nftables(v4: &[String], v6: &[String]) -> String {
    let mut s = String::new();
    s.push_str("# NETSCOPE block set — generated, namespaced, atomically re-appliable.\n");
    s.push_str("# Apply:  sudo nft -f netscope-block.nft\n");
    s.push_str("# Remove: sudo nft delete table inet netscope\n\n");
    // add → delete → recreate: idempotent atomic replace (delete needs it to exist).
    s.push_str("add table inet netscope\n");
    s.push_str("delete table inet netscope\n");
    s.push_str("table inet netscope {\n");
    if !v4.is_empty() {
        s.push_str("\tset blocked4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n");
        s.push_str(&format!("\t\telements = {{ {} }}\n", v4.join(", ")));
        s.push_str("\t}\n");
    }
    if !v6.is_empty() {
        s.push_str("\tset blocked6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n");
        s.push_str(&format!("\t\telements = {{ {} }}\n", v6.join(", ")));
        s.push_str("\t}\n");
    }
    s.push_str("\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n");
    if !v4.is_empty() {
        s.push_str("\t\tip daddr @blocked4 drop\n");
    }
    if !v6.is_empty() {
        s.push_str("\t\tip6 daddr @blocked6 drop\n");
    }
    if v4.is_empty() && v6.is_empty() {
        s.push_str("\t\t# (no targets to block)\n");
    }
    s.push_str("\t}\n}\n");
    s
}

fn pf(v4: &[String], v6: &[String]) -> String {
    // pf tables hold both families; one table, one rule.
    let all: Vec<&String> = v4.iter().chain(v6.iter()).collect();
    let elems: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
    let mut s = String::new();
    s.push_str("# NETSCOPE block — macOS/BSD pf anchor.\n");
    s.push_str("# Apply:  sudo pfctl -a netscope -f netscope-block.pf && sudo pfctl -e\n");
    s.push_str("# Remove: sudo pfctl -a netscope -F all\n\n");
    s.push_str(&format!(
        "table <netscope_block> persist {{ {} }}\n",
        elems.join(", ")
    ));
    s.push_str("block drop out quick to <netscope_block>\n");
    s
}

fn netsh(v4: &[String], v6: &[String]) -> String {
    let all: Vec<&String> = v4.iter().chain(v6.iter()).collect();
    let mut s = String::new();
    s.push_str(":: NETSCOPE block rules — run in an ELEVATED Command Prompt.\n");
    s.push_str(":: Remove: netsh advfirewall firewall delete rule name=all group=\"NETSCOPE\"\n\n");
    // Clear any prior NETSCOPE rules first, so re-running replaces cleanly.
    s.push_str("netsh advfirewall firewall delete rule name=all group=\"NETSCOPE\" >nul 2>&1\n");
    if all.is_empty() {
        s.push_str(":: (no targets to block)\n");
        return s;
    }
    // netsh's remoteip list has a practical length cap — chunk to stay well under it.
    for (i, chunk) in all.chunks(100).enumerate() {
        let list: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
        s.push_str(&format!(
            "netsh advfirewall firewall add rule name=\"NETSCOPE block {}\" dir=out action=block remoteip={} group=\"NETSCOPE\" enable=yes\n",
            i + 1,
            list.join(",")
        ));
    }
    s
}

// ---------------------------------------------------------------------------
// Validation — only addresses that parse reach the output
// ---------------------------------------------------------------------------

/// Split `targets` into validated, normalized IPv4 and IPv6 entries, dropping
/// anything that isn't an IP literal or CIDR. This is the injection guard: a
/// hostname or shell metacharacter can never appear in a generated firewall file.
fn split_valid(targets: &[String]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for t in targets {
        match validate(t.trim()) {
            Some((Family::V4, norm)) if !v4.contains(&norm) => v4.push(norm),
            Some((Family::V6, norm)) if !v6.contains(&norm) => v6.push(norm),
            _ => {}
        }
    }
    (v4, v6)
}

#[derive(PartialEq)]
enum Family {
    V4,
    V6,
}

/// Validate one target as an IP literal or `addr/prefix` CIDR; return its family and
/// a normalized string. `None` for anything malformed.
fn validate(spec: &str) -> Option<(Family, String)> {
    let (addr_str, prefix) = match spec.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (spec, None),
    };
    let addr: IpAddr = addr_str.trim().parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let family = if addr.is_ipv4() {
        Family::V4
    } else {
        Family::V6
    };
    match prefix {
        None => Some((family, addr.to_string())),
        Some(p) => {
            let n: u8 = p.trim().parse().ok()?;
            if n > max {
                return None;
            }
            Some((family, format!("{addr}/{n}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nftables_emits_namespaced_atomic_ruleset() {
        let g = generate(
            Firewall::Nftables,
            &[
                "93.184.216.34".into(),
                "2001:db8::1".into(),
                "10.0.0.0/24".into(),
            ],
        );
        let r = &g.rules;
        // atomic-replace idiom + own table
        assert!(r.contains("add table inet netscope"));
        assert!(r.contains("delete table inet netscope"));
        assert!(r.contains("table inet netscope {"));
        // v4 + v6 sets and drop rules
        assert!(r.contains("set blocked4"));
        assert!(r.contains("93.184.216.34"));
        assert!(r.contains("10.0.0.0/24"));
        assert!(r.contains("ip daddr @blocked4 drop"));
        assert!(r.contains("set blocked6"));
        assert!(r.contains("2001:db8::1"));
        assert!(r.contains("ip6 daddr @blocked6 drop"));
        assert_eq!(g.target_count, 3);
    }

    #[test]
    fn generator_drops_anything_that_isnt_an_address() {
        let g = generate(
            Firewall::Nftables,
            &[
                "93.184.216.34".into(),
                "evil.example.com".into(),  // hostname
                "1.2.3.4; rm -rf /".into(), // injection attempt
                "}; drop table".into(),     // nft injection attempt
                "999.0.0.1".into(),         // not a valid v4
                "10.0.0.0/40".into(),       // bad prefix
            ],
        );
        assert!(g.rules.contains("93.184.216.34"));
        assert!(!g.rules.contains("evil.example.com"));
        assert!(!g.rules.contains("rm -rf"));
        assert!(!g.rules.contains("drop table"));
        assert!(!g.rules.contains("999.0.0.1"));
        assert!(!g.rules.contains("10.0.0.0/40"));
        assert_eq!(g.target_count, 1); // only the one valid address
    }

    #[test]
    fn pf_emits_a_table_and_block_rule_for_both_families() {
        let g = generate(Firewall::Pf, &["8.8.8.8".into(), "2001:db8::5".into()]);
        assert!(g.rules.contains("table <netscope_block> persist"));
        assert!(g.rules.contains("8.8.8.8"));
        assert!(g.rules.contains("2001:db8::5"));
        assert!(g.rules.contains("block drop out quick to <netscope_block>"));
    }

    #[test]
    fn netsh_groups_and_chunks() {
        // 150 addresses → 2 chunks of ≤100, all in the NETSCOPE group.
        let targets: Vec<String> = (0..150)
            .map(|i| format!("203.0.113.{}", i % 254 + 1))
            .collect();
        let g = generate(Firewall::Netsh, &targets);
        assert!(g.rules.contains(r#"delete rule name=all group="NETSCOPE""#));
        let adds = g.rules.matches("add rule").count();
        assert_eq!(adds, 2, "150 targets should chunk into 2 add-rule lines");
        assert!(g.rules.contains(r#"group="NETSCOPE""#));
    }

    #[test]
    fn empty_targets_still_produce_a_valid_namespaced_ruleset() {
        for backend in all_backends() {
            let g = generate(backend, &[]);
            assert_eq!(g.target_count, 0);
            assert!(!g.rules.is_empty());
            // Each names its own namespace so removal still works.
            match backend {
                Firewall::Nftables => assert!(g.rules.contains("table inet netscope")),
                Firewall::Pf => assert!(g.rules.contains("netscope_block")),
                Firewall::Netsh => assert!(g.rules.contains("NETSCOPE")),
            }
        }
    }

    #[test]
    fn backend_round_trips_through_json() {
        for b in all_backends() {
            let j = serde_json::to_string(&b).unwrap();
            let back: Firewall = serde_json::from_str(&j).unwrap();
            assert_eq!(b, back);
        }
        assert_eq!(
            serde_json::to_string(&Firewall::Nftables).unwrap(),
            "\"nftables\""
        );
    }
}
