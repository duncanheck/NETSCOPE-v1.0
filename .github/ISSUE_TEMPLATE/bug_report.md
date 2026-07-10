---
name: Bug report
about: Something didn't work the way it should
title: ""
labels: bug
assignees: ""
---

**Which build?**
- [ ] Windows single-exe (`netscope.exe`)
- [ ] Windows desktop app (Tauri installer)
- [ ] Built from source (`cargo run` / `pnpm dev`)

**Version / build id**
(Shown in the HUD's updater/System panel, or the release/tag you downloaded.)

**What happened**


**What you expected instead**


**Steps to reproduce**
1.
2.
3.

**Were any opt-in features involved?**
- [ ] Packet capture (Npcap / `NETSCOPE_PCAP=1`)
- [ ] Geo/ASN enrichment (MaxMind key)
- [ ] Threat feeds
- [ ] Warden enforcement (`netscope-enforcer`)
- [ ] Remote pairing (C2/C3, watching from another device)
- [ ] None of the above — default setup

**Logs / console output**
(The Windows single-exe shows a console; the Tauri app's agent output goes to stderr —
run it from a terminal if you can, and paste anything relevant.)

```
paste here
```

**Environment**
- OS + version:
- GPU (if the visualization itself looks wrong):
