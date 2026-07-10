# Security Policy

NETSCOPE captures live connection metadata, optionally augments it with packet
headers (Npcap/pcap), and can generate (and, on Linux, apply) firewall rules. That's
a meaningfully sensitive surface for a hobby project, so it gets a real policy
instead of none.

## What's already defended, and where it's documented

Before filing something as a vulnerability, it's worth checking whether it's a known,
deliberate trade-off — the full model lives in
[`docs/threat-model.md`](docs/threat-model.md):

- The agent binds **loopback only** by default; reaching it from another device requires
  explicit opt-in (`NETSCOPE_BIND`) plus the C2 pairing/token flow.
- The WebSocket handshake validates `Origin` against loopback/same-origin to close the
  cross-site WebSocket hijacking (CSWSH) vector — a page on the public internet cannot
  read your connection feed.
- Packet capture (Npcap/pcap, opt-in via `NETSCOPE_PCAP=1`) is headers-only by
  construction: snaplen 96, kernel-filtered to `tcp`/`udp`, aggregated to
  per-conversation counters. Payload never reaches the process.
- The Warden firewall feature is **generate-only** by default — nothing is applied to
  your system unless you separately run the privilege-separated `netscope-enforcer`
  helper, which itself re-checks a never-block floor (loopback/LAN/tailnet) before
  touching anything.
- Self-update (both the single-exe product and the Tauri desktop shell) is
  notify-then-apply over integrity-checked HTTPS downloads, never silent-and-unverified;
  see [`docs/desktop-update.md`](docs/desktop-update.md).

## Reporting a vulnerability

If you find a real security issue — the Origin/CSWSH check can be bypassed, the C2
token flow can be forged or replayed, the enforcer's never-block floor can be
circumvented, packet capture reads more than headers, or anything else that breaks one
of the guarantees above — please report it privately rather than opening a public
issue:

- Preferred: open a [GitHub Security Advisory](../../security/advisories/new) on this
  repo (private by default, visible only to the maintainer until resolved).
- Alternative: email the address on the maintainer's GitHub profile with `NETSCOPE
  security` in the subject.

Include what you found, how to reproduce it, and what it lets an attacker do. This is a
solo-maintained project worked on in bursts, not a company with an SLA — expect an
acknowledgment within a few days to a couple of weeks, not hours, but every report gets
read.

## What's out of scope

- Anything already called out as a known limitation in `docs/threat-model.md` (e.g. a
  native client forging its own `Origin` header — a native attacker already owns the
  machine).
- Issues that require the attacker to already have local code execution as you, or
  admin/root on the host.
- The generic "should this be admin-only" question for features that are already
  documented as opt-in and privilege-separated by design (Warden enforcement, packet
  capture).
