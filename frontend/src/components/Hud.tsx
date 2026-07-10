// The heads-up overlay. Shows the live transport, connection state, the latest
// heartbeat, and the mirrored flow count — i.e. the proof that the pipe works,
// whichever transport is behind it. A toggle flips mock ↔ websocket at runtime to
// demonstrate the abstraction (ROADMAP C1): the rest of the UI doesn't change.

import { memo, useEffect, useRef, useState } from "react";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { useRenderStore } from "../scene/useRenderStore";
import { useWardenStore } from "../store/useWardenStore";
import { useFloatingPanel } from "./useFloatingPanel";
import type { Flow } from "../protocol";
import { CATEGORY_HEX } from "../scene/palette";
import {
  exposureScore,
  gradeColor,
  loadTrend,
  recordSample,
  TREND_SAMPLE_MS,
  type TrendSample,
} from "../store/exposure";
import { exportFilename, flowsToCsv, flowsToJson } from "../store/exportFlows";
import {
  applyUpdate,
  checkForUpdate,
  defaultAgentHttpBase,
  explainSession,
  explainFlow,
  fetchProviders,
  fetchUpdateStatus,
  generateRules,
  previewBlocks,
  threatStatus,
  type Explanation,
  type Firewall,
  type GeneratedRuleset,
  type Plan,
  type Policy,
  type Rule,
  type ProviderId,
  type ProviderStatus,
  type ThreatStatus,
  type UpdateStatus,
} from "../transport";

const STATE_COLOR: Record<string, string> = {
  open: "#3fd6c4",
  connecting: "#ffb347",
  error: "#ff6b6b",
  closed: "#7a8aa0",
  idle: "#7a8aa0",
};


export function Hud() {
  const transportKind = useNetscopeStore((s) => s.transportKind);
  const connectionState = useNetscopeStore((s) => s.connectionState);
  const agent = useNetscopeStore((s) => s.agent);
  const heartbeat = useNetscopeStore((s) => s.lastHeartbeat);
  const heartbeatCount = useNetscopeStore((s) => s.heartbeatCount);
  const flows = useNetscopeStore((s) => s.flows);
  const flowCount = flows.size;
  const needsResync = useNetscopeStore((s) => s.needsResync);
  const mismatch = useNetscopeStore((s) => s.protocolVersionMismatch);
  const attach = useNetscopeStore((s) => s.attach);
  const renderTier = useRenderStore((s) => s.tier);

  const other = transportKind === "mock" ? "websocket" : "mock";

  const { ref, panelProps, handleProps, collapsed, toggleCollapsed, reset } = useFloatingPanel({
    storageKey: "netscope.hud",
    defaultPos: { x: 16, y: 16 },
  });

  return (
    <div className={`hud${collapsed ? " hud--collapsed" : ""}`} ref={ref} {...panelProps}>
      <div className="hud__bar" {...handleProps}>
        <div>
          <div className="hud__title">NETSCOPE</div>
          {!collapsed && (
            <div className="hud__sub">deep-sea network organism — live capture · deep ocean</div>
          )}
        </div>
        <div className="hud__chrome">
          <button
            className="hud__chrome-btn"
            onClick={reset}
            title="reset panel position & size"
            aria-label="reset panel"
          >
            ⟲
          </button>
          <button
            className="hud__chrome-btn"
            onClick={toggleCollapsed}
            title={collapsed ? "expand" : "collapse"}
            aria-label={collapsed ? "expand panel" : "collapse panel"}
          >
            {collapsed ? "▢" : "—"}
          </button>
        </div>
      </div>

      {collapsed ? null : (
      <div className="hud__body">
      <UpdateBanner />

      <dl className="hud__grid">
        <dt>transport</dt>
        <dd>{transportKind}</dd>

        <dt>state</dt>
        <dd style={{ color: STATE_COLOR[connectionState] ?? "#fff" }}>{connectionState}</dd>

        <dt>agent</dt>
        <dd>{agent ? `${agent.name} v${agent.version} (${agent.platform})` : "—"}</dd>

        <dt>heartbeat</dt>
        <dd>{heartbeat ? `#${heartbeat.tick} · seq ${heartbeat.seq}` : "—"}</dd>

        <dt>uptime</dt>
        <dd>{heartbeat ? `${(heartbeat.uptime_ms / 1000).toFixed(0)}s` : "—"}</dd>

        <dt>beats rx</dt>
        <dd>{heartbeatCount}</dd>

        <dt>flows</dt>
        <dd>{flowCount}</dd>

        <dt>gpu tier</dt>
        <dd>{renderTier ? renderTier.label : "probing…"}</dd>
      </dl>

      {mismatch && <div className="hud__warn">⚠ protocol version mismatch</div>}
      {needsResync && <div className="hud__warn">⚠ sequence gap — resync pending (C4)</div>}

      <button className="hud__btn" onClick={() => attach(other)}>
        switch to {other} transport
      </button>

      {transportKind === "websocket" && <PairPanel />}
      {transportKind === "websocket" && <NarratorPanel />}
      {transportKind === "websocket" && <WardenPanel />}

      <ExposureSummary flows={flows} />
      <FlowList flows={flows} />
      <FlowDetail flows={flows} />
      <SupportLink />
      </div>
      )}
    </div>
  );
}

// G2.2 — the support link. NETSCOPE is free and donation-funded; this is one quiet
// line at the bottom of the HUD, link-out only (no in-app payments, no new
// compliance surface). Dismissal persists across reloads (localStorage) so it asks
// once and never nags.
const SUPPORT_KEY = "netscope.support.dismissed";
const SUPPORT_URL = "https://buymeacoffee.com/duncanhecker";

function SupportLink() {
  const [dismissed, setDismissed] = useState(() => {
    try {
      return localStorage.getItem(SUPPORT_KEY) === "1";
    } catch {
      return false;
    }
  });
  if (dismissed) return null;

  const dismiss = () => {
    try {
      localStorage.setItem(SUPPORT_KEY, "1");
    } catch {
      /* private mode / quota — non-fatal */
    }
    setDismissed(true);
  };

  return (
    <div className="support">
      <a className="support__link" href={SUPPORT_URL} target="_blank" rel="noreferrer">
        ☕ support NETSCOPE
      </a>
      <button className="support__x" onClick={dismiss} title="dismiss" aria-label="dismiss support link">
        ✕
      </button>
    </div>
  );
}

// D2 narrator. Pick an AI provider — built-in offline rules, a local Llama via
// Ollama, or Claude — and explain the (scrubbed) current session. The menu shows
// availability and whether the choice keeps data on the machine.
function NarratorPanel() {
  const [providers, setProviders] = useState<ProviderStatus[] | null>(null);
  const [selected, setSelected] = useState<ProviderId>("rules");
  const [model, setModel] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    void fetchProviders(defaultAgentHttpBase()).then((p) => live && setProviders(p));
    return () => {
      live = false;
    };
  }, []);

  // Empty (fetchProviders returns [] on a failed/unreachable fetch) — hide rather
  // than render a broken empty dropdown.
  if (!providers || providers.length === 0) return null;

  const current = providers.find((p) => p.id === selected);
  const localModels = current?.models ?? [];
  // The model the request will use: the explicit pick, or the first detected one.
  const activeModel = model || localModels[0] || "";

  const onExplain = async () => {
    setBusy(true);
    setError(null);
    const result = await explainSession(
      defaultAgentHttpBase(),
      selected,
      selected === "ollama" ? activeModel : undefined,
    );
    if (result.ok) setExplanation(result.explanation);
    else setError(result.error);
    setBusy(false);
  };

  return (
    <div className="narrator">
      <div className="narrator__head">explain my traffic</div>
      <div className="narrator__row">
        <select
          className="narrator__select"
          aria-label="AI provider"
          value={selected}
          onChange={(e) => {
            setSelected(e.target.value as ProviderId);
            setModel(""); // reset model pick when the provider changes
          }}
        >
          {providers.map((p) => (
            <option key={p.id} value={p.id} disabled={!p.available}>
              {p.label}
              {p.available ? "" : " — unavailable"}
            </option>
          ))}
        </select>
        <button
          className="hud__btn narrator__btn"
          onClick={onExplain}
          disabled={busy || !current?.available}
        >
          {busy ? "thinking…" : "explain"}
        </button>
      </div>
      {/* Local-model picker: only when Ollama is selected and has models installed. */}
      {selected === "ollama" && localModels.length > 0 && (
        <select
          className="narrator__select narrator__models"
          aria-label="local model"
          value={activeModel}
          onChange={(e) => setModel(e.target.value)}
        >
          {localModels.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
      )}
      {current && (
        <div className="narrator__detail">
          {current.local ? "🔒 stays on this machine" : "⚠ sends a scrubbed summary off-machine"}{" "}
          · {current.detail}
        </div>
      )}
      {error && <div className="hud__warn">⚠ {error}</div>}
      {explanation && <div className="narrator__out">{explanation.text}</div>}
    </div>
  );
}

// Track E (Warden), E1 — block-policy *preview*. Pick risk classes to block and see
// what the agent's current flows would be cut, with the reason. Nothing is enforced
// (the firewall generator + privileged enforcer are E3/E4); this is read-only and
// protected destinations (loopback, LAN, tailnet) can never be blocked.
const WARDEN_RULES: { rule: Rule; label: string }[] = [
  { rule: { type: "category", value: "tracker" }, label: "trackers" },
  { rule: { type: "flag", value: "plaintext" }, label: "plaintext (unencrypted)" },
  { rule: { type: "flag", value: "unresolved_org" }, label: "unattributable" },
];

const FIREWALLS: { id: Firewall; label: string }[] = [
  { id: "nftables", label: "Linux (nftables)" },
  { id: "netsh", label: "Windows (netsh)" },
  { id: "pf", label: "macOS (pf)" },
];

function WardenPanel() {
  const [on, setOn] = useState<Record<string, boolean>>({ "category:tracker": true, "flag:plaintext": true });
  const [plan, setPlan] = useState<Plan | null>(null);
  const [busy, setBusy] = useState(false);
  const [backend, setBackend] = useState<Firewall>("nftables");
  const [ruleset, setRuleset] = useState<GeneratedRuleset | null>(null);
  const [copied, setCopied] = useState(false);
  // E2: reputation feeds. Status is fetched once; the toggle is only meaningful
  // when at least one feed is loaded (the user ran the downloader script).
  const [threats, setThreats] = useState<ThreatStatus | null>(null);
  const [useThreats, setUseThreats] = useState(false);

  useEffect(() => {
    void threatStatus(defaultAgentHttpBase()).then(setThreats);
  }, []);

  const enforceAvailable = useWardenStore((s) => s.available);

  const key = (r: Rule) => (r.type === "threat" ? "threat" : `${r.type}:${r.value}`);
  const heuristicDeny = WARDEN_RULES.filter(({ rule }) => on[key(rule)]).map(({ rule }) => rule);
  const threatsLoaded = (threats?.indicators ?? 0) > 0;
  const deny: Rule[] =
    useThreats && threatsLoaded ? [...heuristicDeny, { type: "threat" }] : heuristicDeny;

  const onPreview = async () => {
    setBusy(true);
    setRuleset(null);
    setPlan(await previewBlocks(defaultAgentHttpBase(), { allow: [], deny }));
    setBusy(false);
  };

  const onGenerate = async () => {
    setBusy(true);
    setCopied(false);
    setRuleset(await generateRules(defaultAgentHttpBase(), { allow: [], deny }, backend));
    setBusy(false);
  };

  const onCopy = () => {
    if (ruleset) {
      void navigator.clipboard?.writeText(ruleset.rules).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      });
    }
  };

  return (
    <div className="warden">
      <div className="warden__head">
        <span>traffic blocking</span>
        <span className="warden__tag">{enforceAvailable ? "enforce ready" : "preview only"}</span>
      </div>
      <div className="warden__rules">
        {WARDEN_RULES.map(({ rule, label }) => (
          <label key={key(rule)} className="warden__rule">
            <input
              type="checkbox"
              checked={!!on[key(rule)]}
              onChange={(e) => setOn((s) => ({ ...s, [key(rule)]: e.target.checked }))}
            />
            {label}
          </label>
        ))}
        {/* E2: block by reputation. Disabled (and explained) until feeds load. */}
        <label
          className="warden__rule"
          title={
            threatsLoaded
              ? `${threats?.indicators.toLocaleString()} indicators from ${threats?.sources.length} feed${threats?.sources.length === 1 ? "" : "s"}`
              : "run scripts/download-threatfeeds.sh, then restart the agent"
          }
        >
          <input
            type="checkbox"
            checked={useThreats && threatsLoaded}
            disabled={!threatsLoaded}
            onChange={(e) => setUseThreats(e.target.checked)}
          />
          known-bad lists
          {threatsLoaded ? (
            <span className="warden__feedcount">
              {threats?.indicators.toLocaleString()} indicators
            </span>
          ) : (
            <span className="warden__feedcount warden__feedcount--off">no feeds</span>
          )}
        </label>
      </div>
      <button
        className="hud__btn warden__btn"
        onClick={onPreview}
        disabled={busy || deny.length === 0}
      >
        {busy ? "checking…" : "preview blocks"}
      </button>
      {plan && (
        <div className="warden__result">
          <div className="warden__count">
            {plan.blocks.length === 0
              ? `nothing to block (${plan.considered} flows clean)`
              : `${plan.blocks.length} of ${plan.considered} flows would be blocked · ${plan.targets.length} IP${plan.targets.length === 1 ? "" : "s"}`}
          </div>
          {plan.blocks.slice(0, 8).map((b) => (
            <div key={b.flow_id} className="warden__row" title={b.reason}>
              <span className="warden__host">{b.host}</span>
              <span className="warden__why">{b.reason}</span>
            </div>
          ))}
          {plan.blocks.length > 8 && (
            <div className="warden__more">+{plan.blocks.length - 8} more</div>
          )}

          {/* E3: generate a native firewall ruleset from the same policy. */}
          <div className="warden__gen">
            <select
              className="warden__select"
              aria-label="firewall backend"
              value={backend}
              onChange={(e) => setBackend(e.target.value as Firewall)}
            >
              {FIREWALLS.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.label}
                </option>
              ))}
            </select>
            <button className="hud__btn warden__btn" onClick={onGenerate} disabled={busy}>
              generate firewall rules
            </button>
          </div>
        </div>
      )}

      {ruleset && (
        <div className="warden__ruleset">
          <div className="warden__rs-head">
            <span>
              {ruleset.filename} · {ruleset.target_count} target
              {ruleset.target_count === 1 ? "" : "s"}
            </span>
            <button className="warden__copy" onClick={onCopy}>
              {copied ? "copied ✓" : "copy"}
            </button>
          </div>
          <pre className="warden__rules">{ruleset.rules}</pre>
          <div className="warden__hint">apply: {ruleset.apply}</div>
          <div className="warden__hint">remove: {ruleset.remove}</div>
        </div>
      )}

      {/* E6: actual enforcement via the privileged helper (E4), if configured. */}
      <EnforcementPanel policy={{ allow: [], deny }} hasPreview={!!plan} />
    </div>
  );
}

// E6 — the blocking UX. Surfaces the enforcer (E4) when one is configured: apply the
// previewed policy (preview-then-confirm, never silent), see the live blocked list
// with one-click unblock / unblock-all, and a persistent audit log. When no enforcer
// is configured it says so and stays generate-only.
function EnforcementPanel({ policy, hasPreview }: { policy: Policy; hasPreview: boolean }) {
  const available = useWardenStore((s) => s.available);
  const blocked = useWardenStore((s) => s.blocked);
  const audit = useWardenStore((s) => s.audit);
  const busy = useWardenStore((s) => s.busy);
  const last = useWardenStore((s) => s.last);
  const refresh = useWardenStore((s) => s.refresh);
  const apply = useWardenStore((s) => s.apply);
  const unblock = useWardenStore((s) => s.unblock);
  const clearAudit = useWardenStore((s) => s.clearAudit);
  const [confirm, setConfirm] = useState(false);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  if (available === null) return null; // not yet probed

  if (!available) {
    return (
      <div className="enforce enforce--off">
        <div className="enforce__head">
          <span>enforcement off</span>
        </div>
        <div className="warden__hint">
          Generate-only. Windows: install the enforcer service (run{" "}
          <code>install-enforcer.ps1</code> as admin — NETSCOPE detects it
          automatically). Linux: run <code>netscope-enforcer</code> and set{" "}
          <code>NETSCOPE_ENFORCER_SOCKET</code>.
        </div>
      </div>
    );
  }

  const onApply = async () => {
    if (!confirm) {
      setConfirm(true);
      return;
    }
    setConfirm(false);
    await apply(policy, "policy");
  };

  return (
    <div className="enforce">
      <div className="enforce__head">
        <span>enforcement</span>
        <span className="enforce__count">
          {blocked.length} block{blocked.length === 1 ? "" : "s"} active
        </span>
      </div>

      {!hasPreview ? (
        <div className="warden__hint">preview first, then apply.</div>
      ) : confirm ? (
        <div className="enforce__confirm">
          <span>Block via the firewall now?</span>
          <button
            className="hud__btn enforce__btn enforce__btn--danger"
            onClick={onApply}
            disabled={busy}
          >
            confirm
          </button>
          <button className="hud__btn enforce__btn" onClick={() => setConfirm(false)} disabled={busy}>
            cancel
          </button>
        </div>
      ) : (
        <button
          className="hud__btn enforce__btn"
          onClick={onApply}
          disabled={busy || policy.deny.length === 0}
        >
          apply &amp; enforce
        </button>
      )}

      {last && last.configured && (last.added.length > 0 || last.rejected.length > 0 || last.error) && (
        <div className={`warden__hint${last.error ? " enforce__err" : ""}`}>
          {last.error
            ? `⚠ ${last.error}`
            : `blocked ${last.added.length}${last.rejected.length ? `, ${last.rejected.length} protected refused` : ""}`}
        </div>
      )}

      {blocked.length > 0 && (
        <div className="enforce__list">
          {blocked.slice(0, 8).map((ip) => (
            <div key={ip} className="enforce__row">
              <span className="enforce__ip">{ip}</span>
              <button
                className="enforce__x"
                title="unblock"
                onClick={() => void unblock(ip)}
                disabled={busy}
              >
                ✕
              </button>
            </div>
          ))}
          {blocked.length > 8 && <div className="warden__more">+{blocked.length - 8} more</div>}
          <button className="hud__btn enforce__btn" onClick={() => void unblock()} disabled={busy}>
            unblock all
          </button>
        </div>
      )}

      {audit.length > 0 && (
        <details className="enforce__audit">
          <summary>audit log ({audit.length})</summary>
          {audit.slice(0, 12).map((e, i) => (
            <div key={i} className={`enforce__audit-row${e.ok ? "" : " enforce__err"}`}>
              <span className="enforce__audit-time">
                {new Date(e.ts).toLocaleTimeString()}
              </span>
              <span className="enforce__audit-detail">{e.detail}</span>
            </div>
          ))}
          <button className="warden__copy" onClick={clearAudit}>
            clear log
          </button>
        </details>
      )}
    </div>
  );
}

// C3 remote-device entry point. On a phone reaching the agent over the tailnet,
// the WebSocket needs a token; this is where you type the 6-digit pairing code
// shown on the agent host to get one. Loopback needs no token, so this is a
// convenience there and the gate for remote.
function PairPanel() {
  const paired = useNetscopeStore((s) => s.paired);
  const pairing = useNetscopeStore((s) => s.pairing);
  const pairError = useNetscopeStore((s) => s.pairError);
  const pair = useNetscopeStore((s) => s.pair);
  const [code, setCode] = useState("");

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (code.trim().length > 0) void pair(code);
  };

  return (
    <form className="pair" onSubmit={submit}>
      <div className="pair__head">
        <span>pair a device</span>
        {paired && <span className="pair__ok">✓ paired</span>}
      </div>
      <div className="pair__row">
        <input
          className="pair__input"
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={6}
          placeholder="000000"
          aria-label="pairing code"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
        />
        <button className="hud__btn pair__btn" type="submit" disabled={pairing}>
          {pairing ? "pairing…" : "pair"}
        </button>
      </div>
      {pairError && <div className="hud__warn">⚠ {pairError}</div>}
    </form>
  );
}

// Self-update panel (Windows product). Reads the agent's update status on mount and
// stays visible so the updater is observable: it shows the running build, the last
// check result, and a "check now" button. When a newer build is published it offers
// a one-click apply (notify-then-apply — the swap only happens on the user's click).
// Hidden only for dev/unstamped builds or the mock feed (no agent to update).
function UpdateBanner() {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [applying, setApplying] = useState(false);
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  useEffect(() => {
    let live = true;
    void fetchUpdateStatus(defaultAgentHttpBase()).then((s) => live && setStatus(s));
    return () => {
      live = false;
    };
  }, []);

  // Hide for unstamped dev builds (never self-update) and when the agent isn't
  // reachable (mock feed). Once applied, the result message replaces the panel.
  if (result) {
    return (
      <div className={`update ${result.ok ? "update--ok" : "update--err"}`}>
        {result.ok ? "✓ " : "⚠ "}
        {result.message}
      </div>
    );
  }
  if (!status || status.dev) return null;

  const onApply = async () => {
    setApplying(true);
    setResult(await applyUpdate(defaultAgentHttpBase()));
    setApplying(false);
  };

  const onCheck = async () => {
    setChecking(true);
    const next = await checkForUpdate(defaultAgentHttpBase());
    if (next) setStatus(next);
    setChecking(false);
  };

  const upToDate = status.checked && !status.available && !status.error;

  return (
    <div className={`update ${status.available ? "" : "update--idle"}`}>
      <div className="update__head">
        <span>
          {status.available ? "update available" : upToDate ? "up to date" : "updates"}
        </span>
        <span className="update__build">
          {status.available
            ? `build ${status.latest_build}${status.latest_sha ? ` · ${status.latest_sha.slice(0, 7)}` : ""}`
            : `build ${status.current_build}`}
        </span>
      </div>
      {status.available && status.notes && <div className="update__notes">{status.notes}</div>}
      {status.error && <div className="update__notes">last check failed: {status.error}</div>}
      <div className="update__actions">
        <button
          className="hud__btn update__btn update__check"
          onClick={onCheck}
          disabled={checking || applying}
        >
          {checking ? "checking…" : "check now"}
        </button>
        {status.available && (
          <button className="hud__btn update__btn" onClick={onApply} disabled={applying || checking}>
            {applying ? "updating…" : "update & restart"}
          </button>
        )}
      </div>
    </div>
  );
}

// At-a-glance exposure (GROWTH G1.2): the headline is now a graded 0–100 score —
// the "am I okay right now?" answer — computed by the published formula in
// store/exposure.ts, with a rolling sparkline (G1.4) showing where the session has
// been. The counts survive underneath as one-click filter chips: each sets the
// shared filter so the matching nodes isolate in both the list and the 3D scene,
// and clicking the active chip clears it.
function ExposureSummary({ flows }: { flows: Map<string, Flow> }) {
  const filter = useRenderStore((s) => s.filter);
  const setFilter = useRenderStore((s) => s.setFilter);

  const exposure = exposureScore(flows.values());
  // Trend sampling: one sample per interval, whatever the score is then. The ref
  // keeps the interval reading the *current* score without re-arming the timer.
  const scoreRef = useRef(exposure.score);
  scoreRef.current = exposure.score;
  const [trend, setTrend] = useState<TrendSample[]>(() => loadTrend());
  useEffect(() => {
    setTrend(recordSample(scoreRef.current));
    const timer = setInterval(() => setTrend(recordSample(scoreRef.current)), TREND_SAMPLE_MS);
    return () => clearInterval(timer);
  }, []);

  let trackers = 0;
  let plaintext = 0;
  let encrypted = 0;
  for (const f of flows.values()) {
    if (f.category === "tracker" || f.flags.includes("tracker")) trackers++;
    if (f.encrypted) encrypted++;
    else plaintext++;
  }
  const total = flows.size;
  if (total === 0) return null;

  const active = filter.trim().toLowerCase();
  const chip = (token: string, label: string, kind: string) => {
    const on = active === token;
    return (
      <button
        className={`expo__chip expo__chip--${kind}${on ? " expo__chip--on" : ""}`}
        onClick={() => setFilter(on ? "" : token)}
        title={on ? "clear filter" : `isolate ${label}`}
      >
        {label}
      </button>
    );
  };

  return (
    <div className="expo">
      <div
        className="expo__score"
        style={{ color: gradeColor(exposure.grade) }}
        title={`Graded from ${exposure.considered} live external flow${exposure.considered === 1 ? "" : "s"}: trackers (${exposure.trackers}), plaintext (${exposure.plaintext}), unattributable (${exposure.unresolved}). Formula: src/store/exposure.ts.`}
      >
        <span className="expo__num">{exposure.score}</span>
        <span className="expo__grade">{exposure.grade}</span>
        <TrendSparkline samples={trend} />
      </div>
      <div className="expo__chips">
        <span className="expo__lead">exposure</span>
        {chip("encrypted", `${encrypted}/${total} 🔒`, "ok")}
        {plaintext > 0 && chip("plaintext", `${plaintext} plaintext`, "warn")}
        {trackers > 0 && chip("tracker", `${trackers} tracker${trackers === 1 ? "" : "s"}`, "bad")}
        {plaintext === 0 && trackers === 0 && <span className="expo__clean">✓ clean</span>}
      </div>
    </div>
  );
}

// The exposure trend (G1.4): a tiny inline sparkline of the last ~30 minutes of
// score samples. Pure SVG, no chart dependency; inherits the grade colour from the
// score row via currentColor.
function TrendSparkline({ samples }: { samples: TrendSample[] }) {
  if (samples.length < 2) return null;
  const W = 64;
  const H = 18;
  const t0 = samples[0].ts;
  const span = Math.max(samples[samples.length - 1].ts - t0, 1);
  const points = samples
    .map((s) => `${((s.ts - t0) / span) * W},${H - 1 - (s.score / 100) * (H - 2)}`)
    .join(" ");
  return (
    <svg
      className="expo__spark"
      width={W}
      height={H}
      viewBox={`0 0 ${W} ${H}`}
      aria-hidden
    >
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

// The connection list (A2 artifact, now interactive). Reads straight from the
// mirrored store, so it shows real captured flows over the WebSocket transport and
// simulated ones over the mock — identical rendering (the C1 test). Clicking a row
// selects that node in the 3D organism, and vice-versa (shared render store).
function FlowList({ flows }: { flows: Map<string, Flow> }) {
  const selectedId = useRenderStore((s) => s.selectedId);
  const hoveredId = useRenderStore((s) => s.hoveredId);
  const select = useRenderStore((s) => s.select);
  const hover = useRenderStore((s) => s.hover);
  // The filter lives in the render store so typing here also isolates the matching
  // nodes in the 3D scene, not just this list.
  const query = useRenderStore((s) => s.filter);
  const setQuery = useRenderStore((s) => s.setFilter);

  // Most active first; dead-but-lingering flows sink to the bottom.
  const sorted = [...flows.values()].sort(
    (a, b) => Number(b.alive) - Number(a.alive) || b.activity - a.activity,
  );

  // QoL: free-text filter across host, process, org, category, ip, and port.
  const q = query.trim().toLowerCase();
  const shown = q
    ? sorted.filter((f) =>
        [f.name, f.process?.name, f.asn?.org, f.category, f.ip, String(f.port)]
          .filter(Boolean)
          .some((field) => (field as string).toLowerCase().includes(q)),
      )
    : sorted;

  // G4.1: export what's on screen (the filtered view, so a narrowed list
  // exports narrowed) as JSON for tooling or CSV for a spreadsheet.
  const exportAs = (kind: "json" | "csv") => {
    const body = kind === "json" ? flowsToJson(shown) : flowsToCsv(shown);
    const mime = kind === "json" ? "application/json" : "text/csv";
    const url = URL.createObjectURL(new Blob([body], { type: mime }));
    const a = document.createElement("a");
    a.href = url;
    a.download = exportFilename(kind);
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flows">
      <div className="flows__head">
        <span>connections</span>
        <span className="flows__tools">
          {shown.length > 0 && (
            <>
              <button className="flows__export" onClick={() => exportAs("csv")} title="export the listed connections as CSV">
                ⤓ csv
              </button>
              <button className="flows__export" onClick={() => exportAs("json")} title="export the listed connections as JSON">
                ⤓ json
              </button>
            </>
          )}
          <span>{q ? `${shown.length}/${flows.size}` : flows.size}</span>
        </span>
      </div>
      <input
        className="flows__search"
        type="search"
        placeholder="filter — host, process, org…"
        aria-label="filter connections"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      {shown.length === 0 ? (
        <div className="flows__empty">{q ? "no matching connections" : "no active connections"}</div>
      ) : (
        <div className="flows__list">
          {shown.map((f) => (
            <FlowRow
              key={f.id}
              flow={f}
              selected={f.id === selectedId}
              hovered={f.id === hoveredId}
              select={select}
              hover={hover}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// Memoized so a delta only re-renders the rows whose flow actually changed — with
// 150–200 live connections, re-rendering every row a few times a second is a real
// main-thread cost that competes with the render loop (felt as stutter, especially
// in the desktop WebView). The store keeps unchanged flows' references stable across
// deltas, and select/hover are stable store actions, so memo skips the rest.
const FlowRow = memo(function FlowRow({
  flow,
  selected,
  hovered,
  select,
  hover,
}: {
  flow: Flow;
  selected: boolean;
  hovered: boolean;
  select: (id: string | null) => void;
  hover: (id: string | null) => void;
}) {
  const proc = flow.process ? `${flow.process.name}` : "protected";
  const cls = `flow${flow.alive ? "" : " flow--dead"}${selected ? " flow--selected" : ""}${
    hovered ? " flow--hovered" : ""
  }`;
  return (
    <div
      className={cls}
      title={flow.id}
      onClick={() => select(flow.id)}
      onPointerEnter={() => hover(flow.id)}
      onPointerLeave={() => hover(null)}
    >
      <span className="flow__dot" style={{ background: CATEGORY_HEX[flow.category] }} />
      <div className="flow__main">
        <div className="flow__name">{flow.name}</div>
        <div className="flow__meta">
          {flow.protocol.toUpperCase()} · :{flow.port} ·{" "}
          {flow.encrypted ? (
            <span className="flow__lock">🔒 encrypted</span>
          ) : (
            <span className="flow__plain">plaintext</span>
          )}
        </div>
      </div>
      <span className="flow__proc">{proc}</span>
    </div>
  );
});

// D2, per-node: explain the single selected endpoint with a chosen AI provider —
// defaulting to a *local* one (built-in rules, always on; or a local Ollama model)
// so the explanation can stay entirely on the machine. Mirrors the session
// NarratorPanel but scoped to one flow, and only when an agent is attached.
function NodeExplain({ flow }: { flow: Flow }) {
  const transportKind = useNetscopeStore((s) => s.transportKind);
  const [providers, setProviders] = useState<ProviderStatus[] | null>(null);
  const [selected, setSelected] = useState<ProviderId>("rules");
  const [model, setModel] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (transportKind !== "websocket") return;
    let live = true;
    void fetchProviders(defaultAgentHttpBase()).then((p) => {
      if (!live) return;
      setProviders(p);
      // Default to the first available *local* provider (keeps it on-machine), else
      // the first available one.
      const pref = p.find((x) => x.available && x.local) ?? p.find((x) => x.available);
      if (pref) setSelected(pref.id);
    });
    return () => {
      live = false;
    };
  }, [transportKind]);

  // A new selection is a fresh question — drop the previous answer.
  useEffect(() => {
    setExplanation(null);
    setError(null);
  }, [flow.id]);

  // Hide on mock or when the provider fetch came back empty (unreachable agent).
  if (transportKind !== "websocket" || !providers || providers.length === 0) return null;

  const current = providers.find((p) => p.id === selected);
  const localModels = current?.models ?? [];
  const activeModel = model || localModels[0] || "";

  const onExplain = async () => {
    setBusy(true);
    setError(null);
    const result = await explainFlow(
      defaultAgentHttpBase(),
      selected,
      flow.id,
      selected === "ollama" ? activeModel : undefined,
    );
    if (result.ok) setExplanation(result.explanation);
    else setError(result.error);
    setBusy(false);
  };

  return (
    <div className="narrator narrator--node">
      <div className="narrator__head">explain this endpoint</div>
      <div className="narrator__row">
        <select
          className="narrator__select"
          aria-label="AI provider"
          value={selected}
          onChange={(e) => {
            setSelected(e.target.value as ProviderId);
            setModel("");
          }}
        >
          {providers.map((p) => (
            <option key={p.id} value={p.id} disabled={!p.available}>
              {p.label}
              {p.available ? "" : " — unavailable"}
            </option>
          ))}
        </select>
        <button
          className="hud__btn narrator__btn"
          onClick={onExplain}
          disabled={busy || !current?.available}
        >
          {busy ? "thinking…" : "explain"}
        </button>
      </div>
      {selected === "ollama" && localModels.length > 0 && (
        <select
          className="narrator__select narrator__models"
          aria-label="local model"
          value={activeModel}
          onChange={(e) => setModel(e.target.value)}
        >
          {localModels.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
      )}
      {current && (
        <div className="narrator__detail">
          {current.local ? "🔒 stays on this machine" : "⚠ sends a scrubbed summary off-machine"}
        </div>
      )}
      {error && <div className="hud__warn">⚠ {error}</div>}
      {explanation && <div className="narrator__out">{explanation.text}</div>}
    </div>
  );
}

// Detail panel for the selected node — the slide-in inspector (salvaged concept).
function FlowDetail({ flows }: { flows: Map<string, Flow> }) {
  const selectedId = useRenderStore((s) => s.selectedId);
  const select = useRenderStore((s) => s.select);
  const focusId = useRenderStore((s) => s.focusId);
  const setFocus = useRenderStore((s) => s.setFocus);
  // E6: per-flow block, when an enforcer is available (shared state).
  const enforceAvailable = useWardenStore((s) => s.available);
  const blocked = useWardenStore((s) => s.blocked);
  const enforceBusy = useWardenStore((s) => s.busy);
  const blockIpAction = useWardenStore((s) => s.block);
  const unblockAction = useWardenStore((s) => s.unblock);
  const flow = selectedId ? flows.get(selectedId) : undefined;
  if (!flow) return null;

  const loc = flow.location;
  const place = loc
    ? [loc.city, loc.country].filter(Boolean).join(", ") || "—"
    : flow.category === "local"
      ? "local network"
      : "—";

  return (
    <div className="detail">
      <div className="detail__head">
        <span
          className="flow__dot"
          style={{ background: CATEGORY_HEX[flow.category] }}
        />
        <span className="detail__name">{flow.name}</span>
        <button className="detail__close" onClick={() => select(null)} aria-label="close">
          ✕
        </button>
      </div>
      <dl className="detail__grid">
        <dt>category</dt>
        <dd>{flow.category}</dd>
        <dt>endpoint</dt>
        <dd>
          {flow.ip}:{flow.port} / {flow.protocol.toUpperCase()}
        </dd>
        <dt>security</dt>
        <dd className={flow.encrypted ? "flow__lock" : "flow__plain"}>
          {flow.encrypted ? "encrypted" : "plaintext"}
        </dd>
        <dt>process</dt>
        <dd>{flow.process ? `${flow.process.name} (pid ${flow.process.pid})` : "protected"}</dd>
        <dt>org</dt>
        <dd>{flow.asn ? `${flow.asn.org} (AS${flow.asn.number})` : "—"}</dd>
        <dt>location</dt>
        <dd>{place}</dd>
        <dt>activity</dt>
        <dd>{Math.round(flow.activity * 100)}%</dd>
        <dt>flags</dt>
        <dd>
          {flow.flags.length === 0 ? (
            "—"
          ) : (
            <span className="chips">
              {flow.flags.map((f) => (
                <span key={f} className={`chip chip--${f}`}>
                  {f.replace("_", " ")}
                </span>
              ))}
            </span>
          )}
        </dd>
      </dl>
      {/* Drill-down: focus this node — the camera flies in, its relatives stay lit,
          the rest of the organism dims. */}
      <button
        className={`hud__btn detail__focus${focusId === flow.id ? " detail__focus--on" : ""}`}
        onClick={() => setFocus(flow.id)}
      >
        {focusId === flow.id ? "exit focus" : "explore connections"}
      </button>
      {/* D2 per-node: explain this single endpoint with a local (or cloud) AI. */}
      <NodeExplain flow={flow} />
      {/* E6: block this specific endpoint (only when enforcement is available and
          the destination isn't local — the enforcer would refuse a protected IP). */}
      {enforceAvailable && flow.category !== "local" && (
        blocked.includes(flow.ip) ? (
          <button
            className="hud__btn enforce__flow-btn enforce__flow-btn--on"
            onClick={() => void unblockAction(flow.ip)}
            disabled={enforceBusy}
          >
            unblock this endpoint
          </button>
        ) : (
          <button
            className="hud__btn enforce__flow-btn"
            onClick={() => void blockIpAction(flow.ip)}
            disabled={enforceBusy}
          >
            block this endpoint
          </button>
        )
      )}
    </div>
  );
}
