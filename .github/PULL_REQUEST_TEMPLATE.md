## What this changes and why



## Checklist

- [ ] `cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test --all` pass (`agent/`)
- [ ] `pnpm typecheck && pnpm test && pnpm build` pass (`frontend/`)
- [ ] If the Rust protocol crate's types changed: TS bindings regenerated
      (`cargo test -p netscope-protocol export_bindings`) and committed
- [ ] Docs updated if user-visible behavior changed (`README.md`, `docs/`, or `ARCHITECTURE.md`)
- [ ] For anything beyond a small fix: there's a linked issue discussing the approach first
