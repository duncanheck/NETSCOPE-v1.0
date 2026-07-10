// GPU capability gate for the ocean environment (PITFALLS B2). The fBm+warp pass
// is the frame's most expensive work; on a weak GPU, 5 octaves at full res melts
// the budget. Rather than sniff the user-agent (a lie — a phone can outrun a
// laptop), we *measure*: at startup we render a deliberately heavy fragment a few
// times to a small target, force a GPU sync, and time it. The measured cost picks
// the tier (octave count + RT scale + particle density).
//
// The probe is coarse by design — a single wall-clock read of a forced GPU flush,
// not a rigorous benchmark — so the thresholds are conservative and biased toward
// the richer tier unless the GPU is clearly struggling. A `?renderTier=` query
// override exists for manual testing.

import * as THREE from "three";

export interface RenderTier {
  /** fBm octaves injected into the ocean shader. */
  octaves: number;
  /** Render-target scale vs. drawing-buffer size (0.5 = half-res). */
  rtScale: number;
  /** Multiplier on marine-snow particle counts. */
  snowDensity: number;
  /** False when the user asked for reduced motion — drift freezes. */
  animate: boolean;
  /** Post-processing bloom (B6) — UnrealBloom on the composited frame. Gated to
   *  the HIGH tier, so a weak/mobile GPU (which measures slow → LOW) skips the
   *  extra passes. Overridable with `?bloom=on|off`. */
  bloom: boolean;
  /** Icosphere subdivision for the organism nodes. A capable GPU gets rounder,
   *  glassier cells (4); a weak/mobile one stays at the cheaper 3 — same
   *  measured-tier discipline as the octave/RT-scale knobs above, since node
   *  geometry is the one thing that scales with the (up to 512) instance count. */
  nodeDetail: number;
  /** Short label for the HUD diagnostics line. */
  label: string;
}

const HIGH: Omit<RenderTier, "animate"> = {
  octaves: 5,
  rtScale: 0.5,
  snowDensity: 1.0,
  bloom: true,
  nodeDetail: 4,
  label: "high · 5 octaves · ½-res · bloom",
};
const LOW: Omit<RenderTier, "animate"> = {
  octaves: 3,
  rtScale: 0.4,
  snowDensity: 0.5,
  bloom: false,
  nodeDetail: 3,
  label: "low · 3 octaves · ⅖-res",
};

/** Apply the user's Settings-panel overrides on top of the measured/probed tier.
 *  `tierPref`/`bloomPref` of "auto" leave the measured value untouched; an explicit
 *  high/low or on/off wins. Returns a fresh object so a change re-keys DeepOcean's
 *  render rig (rebuilding the bloom composer) — the override applies live. */
export function applyTierPrefs(
  base: RenderTier,
  tierPref: "auto" | "high" | "low",
  bloomPref: "auto" | "on" | "off",
): RenderTier {
  let tier = base;
  if (tierPref === "high") tier = { ...HIGH, animate: base.animate };
  else if (tierPref === "low") tier = { ...LOW, animate: base.animate };

  let bloom = tier.bloom;
  if (bloomPref === "on") bloom = true;
  else if (bloomPref === "off") bloom = false;

  const forced =
    (tierPref !== "auto" ? ` · tier ${tierPref} (forced)` : "") +
    (bloomPref !== "auto" ? ` · bloom ${bloomPref} (forced)` : "");
  return { ...tier, bloom, label: tier.label + forced };
}

/** Heavy probe fragment: 5-octave warped fBm, structurally like the real shader
 *  so its cost is representative, but standalone so the probe owns no state. */
const PROBE_FRAGMENT = /* glsl */ `
  precision highp float;
  varying vec2 vUv;
  uniform float uTime;
  float hash(vec2 p){ return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
  float noise(vec2 p){
    vec2 i = floor(p), f = fract(p);
    float a = hash(i), b = hash(i + vec2(1.0, 0.0));
    float c = hash(i + vec2(0.0, 1.0)), d = hash(i + vec2(1.0, 1.0));
    vec2 u = f * f * (3.0 - 2.0 * f);
    return mix(a, b, u.x) + (c - a) * u.y * (1.0 - u.x) + (d - b) * u.x * u.y;
  }
  float fbm(vec2 p){
    float v = 0.0, a = 0.5;
    for (int i = 0; i < 5; i++){ v += a * noise(p); p *= 2.0; a *= 0.5; }
    return v;
  }
  void main(){
    vec2 p = vUv * 6.0 + uTime;
    vec2 q = vec2(fbm(p), fbm(p + 5.2));
    vec2 r = vec2(fbm(p + 4.0 * q), fbm(p + 4.0 * q + 2.8));
    float n = fbm(p + 4.0 * r);
    gl_FragColor = vec4(vec3(n), 1.0);
  }
`;
const PROBE_VERTEX = /* glsl */ `
  varying vec2 vUv;
  void main(){ vUv = uv; gl_Position = vec4(position.xy, 0.0, 1.0); }
`;

function queryOverride(): "high" | "low" | null {
  if (typeof window === "undefined") return null;
  const v = new URLSearchParams(window.location.search).get("renderTier");
  return v === "high" || v === "low" ? v : null;
}

/** `?bloom=on|off` forces the B6 bloom pass on/off, independent of tier. */
export function bloomOverride(): boolean | null {
  if (typeof window === "undefined") return null;
  const v = new URLSearchParams(window.location.search).get("bloom");
  if (v === "on") return true;
  if (v === "off") return false;
  return null;
}

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true
  );
}

/**
 * Probe the GPU and choose a render tier. Renders {@link PROBE_FRAGMENT} a handful
 * of times to a 512×288 target and times a forced read-back. Any failure (no
 * float RT, lost context) falls back to the LOW tier — never throws into render.
 */
export function probeRenderTier(gl: THREE.WebGLRenderer): RenderTier {
  const animate = !prefersReducedMotion();

  // A `?bloom=on|off` override wins over whatever the tier would default to.
  const withBloom = (tier: RenderTier): RenderTier => {
    const o = bloomOverride();
    if (o === null) return tier;
    return { ...tier, bloom: o, label: `${tier.label} · bloom ${o ? "on" : "off"} (forced)` };
  };

  const override = queryOverride();
  if (override) {
    const base = override === "high" ? HIGH : LOW;
    return withBloom({ ...base, animate, label: `${base.label} (forced)` });
  }

  const base = (() => {
    try {
      const W = 512;
      const H = 288;
      const target = new THREE.WebGLRenderTarget(W, H);
      const scene = new THREE.Scene();
      const cam = new THREE.Camera();
      const material = new THREE.ShaderMaterial({
        vertexShader: PROBE_VERTEX,
        fragmentShader: PROBE_FRAGMENT,
        uniforms: { uTime: { value: 0 } },
      });
      const quad = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), material);
      scene.add(quad);

      const FRAMES = 12;
      const prevTarget = gl.getRenderTarget();
      const start = performance.now();
      for (let i = 0; i < FRAMES; i++) {
        material.uniforms.uTime.value = i * 0.13;
        gl.setRenderTarget(target);
        gl.render(scene, cam);
      }
      // Force the GPU to finish so the timing reflects real work, not just queue
      // submission. readRenderTargetPixels is a synchronous flush.
      const px = new Uint8Array(4);
      gl.readRenderTargetPixels(target, 0, 0, 1, 1, px);
      const elapsed = performance.now() - start;
      gl.setRenderTarget(prevTarget);

      target.dispose();
      material.dispose();
      quad.geometry.dispose();

      // ~512×288×12 ≈ 1.77 Mpx of heavy fBm. Comfortably under budget → HIGH.
      // The threshold is deliberately lenient; only a clearly slow GPU drops.
      const perFrame = elapsed / FRAMES;
      // eslint-disable-next-line no-console
      console.info(
        `[netscope] GPU probe: ${elapsed.toFixed(1)}ms / ${FRAMES} frames ` +
          `(${perFrame.toFixed(2)}ms each) → tier ${perFrame < 4 ? "high" : "low"}`,
      );
      return perFrame < 4 ? HIGH : LOW;
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn("[netscope] GPU probe failed — defaulting to low tier", err);
      return LOW;
    }
  })();

  return withBloom({ ...base, animate });
}
