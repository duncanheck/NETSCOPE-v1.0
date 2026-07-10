# Contributing

NETSCOPE is solo-maintained and worked on in bursts — heads-down sprints followed by
quiet stretches, not continuous attention. That shapes what "contributing" looks like
here.

## Bug reports

The most useful contribution, and always welcome. Please use the
[bug report template](.github/ISSUE_TEMPLATE/bug_report.md) — it asks which build
you're running (Windows single-exe, Tauri desktop, or from source) and whether an
opt-in feature (Npcap, geo/ASN, threat feeds, the enforcer) was involved, since those
are the paths most likely to fail in an environment-specific way.

## Feature requests

Also welcome — use the
[feature request template](.github/ISSUE_TEMPLATE/feature_request.md). Worth reading
[`planning/ROADMAP.md`](planning/ROADMAP.md) and [`planning/GROWTH.md`](planning/GROWTH.md)
first: both are live documents of what's planned or deliberately deferred, so a request
might already be tracked (or already rejected, with the reasoning written down).

## Pull requests

Small, focused PRs are the ones most likely to get merged: a bug fix, a docs
correction, a small platform-compatibility fix. For anything larger — a new feature, a
new subsystem, a change to the wire protocol or the capture pipeline — please open an
issue first to discuss the approach before writing code. This is a project with
deliberate architectural stances (see [`ARCHITECTURE.md`](ARCHITECTURE.md) and
[`planning/PITFALLS.md`](planning/PITFALLS.md)); a PR that goes against one of those
without prior discussion is unlikely to be merged as-is, even if the code itself is
fine.

Before opening a PR:

- `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all`
  in `agent/` (CI runs this, plus the `pcap` feature separately).
- `pnpm typecheck && pnpm test && pnpm build` in `frontend/`.
- If you changed the Rust protocol crate's types, regenerate the TS bindings:
  `cd agent && cargo test -p netscope-protocol export_bindings`, then
  `cd frontend && pnpm typecheck` to confirm nothing drifted. CI fails the build on
  drift, so this isn't optional.

Reviews happen in bursts, not on a fixed cadence — an open PR might sit for a while
between maintainer passes. That's not a rejection; it's the maintenance model.

## Getting oriented

[`ARCHITECTURE.md`](ARCHITECTURE.md) explains the subsystem-by-subsystem reasoning;
`docs/` has focused deep-dives per milestone (protocol, ring buffer, performance,
threat model); `planning/ROADMAP.md` and `planning/GROWTH.md` are the engineering and
product roadmaps, both kept current as milestones land.
