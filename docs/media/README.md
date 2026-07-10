# docs/media

Drop-zone for the assets the main `README.md` hero section already references. Add a
file with the exact name below and it activates in the README with no further edits —
these paths are wired in already.

| File | Used for | Suggested spec |
|---|---|---|
| `demo.gif` | README hero, animates inline on GitHub | 10–20s, the organism reacting to live traffic + a HUD interaction (arrangement switch, focus a node, cinematic mode toggle). Under ~10MB so it loads fast on GitHub. |
| `screenshot.png` | Fallback static image / social preview source | A single crisp frame — ideally the same moment the GIF opens on, dense enough to read as "network visualizer" at a glance. |
| `demo-video.md` | Longer video, not committed as a binary | A one-line file containing just the hosted URL (YouTube/etc.) once the 60–90s cut is up — the README links to it if present. |

Until `demo.gif` exists, the README shows a plain "demo coming soon" line instead of a
broken image.
