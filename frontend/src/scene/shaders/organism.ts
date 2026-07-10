// Organism node shaders (ROADMAP B3). Endpoints are soft pulsing volumes: an
// InstancedMesh of icospheres whose surface is displaced by 3D simplex noise (a
// membrane wobble) and shaded with a fresnel rim so each node reads as a
// bioluminescent cell glowing at its silhouette. A second instanced layer draws
// additive glow halos as bloom accents (true bloom is B6).
//
// Everything that varies per node — colour, activity, the exposed/plaintext flag,
// a phase offset, selection — arrives as a per-instance attribute, so the whole
// organism is one draw call (PITFALLS B3: InstancedMesh from the first commit).
// Picking is handled on the CPU against the undisplaced spheres; the displacement
// here is cosmetic only.

import { snoise3 as SNOISE3 } from "./noise";

// `instanceMatrix`, `position`, `normal`, the model/view/projection matrices and
// `normalMatrix` are all provided by three's ShaderMaterial prefix (USE_INSTANCING
// is set automatically for an InstancedMesh).
export const nodeVertexShader = /* glsl */ `
  attribute vec3 aColor;
  attribute float aActivity;
  attribute float aPhase;
  attribute float aExposed;   // 1.0 = plaintext/exposed
  attribute float aSeverity;  // 0–1 risk grade (G1.3): tracker∧plaintext worst
  attribute float aSelected;  // 1.0 = selected
  attribute float aAlive;     // 0.0 = closed but lingering
  attribute float aDim;       // focus dimming: 1.0 lit, <1.0 backgrounded

  uniform float uTime;

  varying vec3 vColor;
  varying float vActivity;
  varying float vExposed;
  varying float vSeverity;
  varying float vSelected;
  varying float vAlive;
  varying float vDim;
  varying float vPhase;
  varying vec3 vViewNormal;
  varying vec3 vViewPos;
  varying vec3 vSphere;   // stable object-space direction, for the surface pattern

  ${SNOISE3}

  void main() {
    // Membrane wobble. Two octaves: a low-frequency swell that reads as a soft
    // breathing volume (not a lumpy potato — the old single high-freq octave made
    // busy nodes faceted), plus a faint high-freq shimmer for organic surface life.
    // Amplitude stays gentle so the silhouette reads round; activity mostly drives
    // the swell, selection adds a small bloom.
    float t = uTime * 0.55 + aPhase;
    float swell = snoise(normal * 1.1 + vec3(0.0, 0.0, t));
    float detail = snoise(normal * 3.3 + vec3(0.0, t * 1.4, 0.0));
    float amp = 0.035 + 0.10 * aActivity + 0.045 * aSelected;
    float disp = swell * amp + detail * amp * 0.28;
    vec3 displaced = position + normal * disp;

    vec4 mv = modelViewMatrix * instanceMatrix * vec4(displaced, 1.0);
    vViewPos = mv.xyz;
    // Instances are translate+uniform-scale only (no rotation), so the base normal
    // through normalMatrix is a fine view-space normal for the rim term.
    vViewNormal = normalize(normalMatrix * (mat3(instanceMatrix) * normal));
    // Undisplaced sphere direction: a stable surface coordinate for the fragment's
    // technological patterning, so the grid/panels sit on the shell rather than
    // swimming with the wobble.
    vSphere = normalize(position);

    vColor = aColor;
    vActivity = aActivity;
    vExposed = aExposed;
    vSeverity = aSeverity;
    vSelected = aSelected;
    vAlive = aAlive;
    vDim = aDim;
    vPhase = aPhase;
    gl_Position = projectionMatrix * mv;
  }
`;

export const nodeFragmentShader = /* glsl */ `
  precision highp float;

  uniform float uTime;

  varying vec3 vColor;
  varying float vActivity;
  varying float vExposed;
  varying float vSeverity;
  varying float vSelected;
  varying float vAlive;
  varying float vDim;
  varying float vPhase;
  varying vec3 vViewNormal;
  varying vec3 vViewPos;
  varying vec3 vSphere;

  #define TAU 6.2831853

  void main() {
    vec3 N = normalize(vViewNormal);
    vec3 V = normalize(-vViewPos);
    float facing = clamp(dot(N, V), 0.0, 1.0);

    // Layered fresnel: a wide soft halo (pow 2) that fills the body with rim light,
    // and a tight bright edge (pow 6) that draws a crisp glowing silhouette. The
    // pair is what turns a flat ball into a luminous membrane.
    float f = 1.0 - facing;
    float rimSoft = f * f;
    float rimEdge = pow(f, 6.0);

    // Translucent depth: light scatters *through* a cell, so the part facing us
    // glows from within. Brighter core toward centre, breathing with activity.
    float pulse = 0.6 + 0.4 * sin(uTime * 2.0 + vActivity * 6.2831);
    float inner = mix(0.10, 0.5, vActivity) * pulse;
    vec3 col = vColor * inner * (0.35 + 0.85 * facing);

    // --- Technological shell (the "data core" read) ------------------------
    // A stable surface pattern built from the undisplaced sphere direction, so it
    // sits ON the shell like an instrument casing rather than swimming with the
    // wobble. Three cues, all in the node's own hue:
    //   1. a lat/long wireframe (meridians + parallels) — a sensor globe;
    //   2. faint panel cells filling the quads, for a machined surface;
    //   3. a bright holographic scan-band sweeping pole to pole.
    // Per-node phase rotates the grid + offsets the scan so no two are identical.
    vec3 s = normalize(vSphere);
    float lon = atan(s.z, s.x) + vPhase * TAU;   // −π..π, rotated per node
    float lat = asin(clamp(s.y, -1.0, 1.0));      // −π/2..π/2

    // Wireframe: thin bright seams where the lat/long grid crosses. fwidth keeps
    // the lines a roughly constant screen width so they don't alias to noise.
    float gx = abs(fract(lon / TAU * 12.0) - 0.5);
    float gy = abs(fract(lat / 3.14159 * 8.0 + 0.5) - 0.5);
    float lw = 0.06;
    float grid = smoothstep(lw, 0.0, min(gx, gy));

    // Panel cells: darken the quad interiors a touch, alternating like plating.
    float cell = step(0.5, fract(floor(lon / TAU * 12.0) * 0.5 + floor(lat / 3.14159 * 8.0) * 0.5));
    float panel = 0.85 + 0.15 * cell;

    // Holo scan: a soft band travelling pole→pole, brightest at its crest.
    float scanPos = fract(lat / 3.14159 + 0.5 - uTime * 0.12 + vPhase);
    float scan = smoothstep(0.10, 0.0, abs(scanPos - 0.5)) * (0.5 + 0.5 * vActivity);

    // Detail lives on the body (facing) and fades at the rim so the silhouette
    // stays a clean glowing membrane. Brighter with activity — a busy node's
    // casing lights up.
    float shellVis = facing * facing * (0.5 + 0.7 * vActivity);
    vec3 seam = mix(vColor, vec3(1.0), 0.55);
    col *= panel;
    col += seam * grid * shellVis * 1.1;
    col += seam * scan * shellVis * 0.9;

    // Rim light in the node's own hue, warmed slightly toward white at the very
    // edge for a wet, glassy read.
    col += vColor * rimSoft * 1.35;
    col += mix(vColor, vec3(1.0), 0.4) * rimEdge * 1.7;

    // A soft specular sheen from a fixed key light, kept subtle — just enough to
    // catch the eye as a moving highlight when the camera orbits.
    vec3 L = normalize(vec3(0.4, 0.7, 0.6));
    vec3 H = normalize(L + V);
    float spec = pow(max(dot(N, H), 0.0), 24.0);
    col += vec3(0.6, 0.85, 1.0) * spec * 0.5 * facing;

    // Exposed / plaintext: the old treatment washed these toward grey, which read
    // as "boring", not "at risk". Now an unencrypted endpoint keeps its category
    // hue and wears an amber hazard signal instead — a rotating beacon band
    // sweeping the shell plus a hot pulsing rim: "broadcasting in the clear".
    if (vExposed > 0.5) {
      vec3 amber = vec3(1.0, 0.62, 0.14);
      // The beacon: a bright longitude band circling the node.
      float beaconPos = fract(lon / TAU - uTime * 0.22 + vPhase);
      float beacon = smoothstep(0.14, 0.0, abs(beaconPos - 0.5));
      col = mix(col, col * 0.7 + amber * 0.30, 0.5);            // warm amber cast, hue kept
      col += amber * beacon * facing * (0.55 + 0.6 * vActivity); // the sweep
      float warn = 0.6 + 0.4 * sin(uTime * 3.2 + vPhase * TAU);
      col += amber * warn * (0.30 * rimSoft + 1.0 * rimEdge);    // hot beacon rim
    }

    // Severity rim (G1.3) — the *should I worry* channel, independent of category
    // hue: flagged nodes carry a warm warning rim whose heat tracks the risk grade
    // (tracker∧plaintext > tracker > plaintext > unresolved). A slow pulse keeps it
    // alive without reading as activity.
    if (vSeverity > 0.0) {
      float sPulse = 0.7 + 0.3 * sin(uTime * 2.6 + vViewPos.x);
      col += vec3(1.0, 0.26, 0.14) * vSeverity * sPulse * (0.3 + 1.5 * rimSoft);
    }

    // Selection: a cool white core lift so the chosen node stands out.
    col += vec3(0.5, 0.8, 0.9) * vSelected * (0.25 + 0.5 * rimSoft);

    // Closed-but-lingering nodes fade toward dark.
    col *= mix(0.25, 1.0, vAlive);

    // Focus: nodes outside the focused relationship recede into the water.
    col *= vDim;

    gl_FragColor = vec4(col, 1.0);
  }
`;

// Glow halos: an instanced camera-facing quad per node, additively blended, giving
// each cell a soft bloom accent. `instanceMatrix` carries only the node's position;
// the quad is sized in view space by aSize so it always faces the camera.
export const glowVertexShader = /* glsl */ `
  attribute vec3 aColor;
  attribute float aSize;
  attribute float aActivity;
  attribute float aSeverity;
  attribute float aSelected;
  attribute float aAlive;
  attribute float aDim;

  varying vec2 vUv;
  varying vec3 vColor;
  varying float vActivity;
  varying float vSeverity;
  varying float vSelected;
  varying float vAlive;
  varying float vDim;

  void main() {
    vUv = uv;
    vColor = aColor;
    vActivity = aActivity;
    vSeverity = aSeverity;
    vSelected = aSelected;
    vAlive = aAlive;
    vDim = aDim;

    // Node centre in view space, then offset by the quad corner so it billboards.
    vec4 center = modelViewMatrix * instanceMatrix * vec4(0.0, 0.0, 0.0, 1.0);
    float size = aSize * (1.0 + 0.6 * aSelected);
    vec3 viewPos = center.xyz + vec3(position.xy * size, 0.0);
    gl_Position = projectionMatrix * vec4(viewPos, 1.0);
  }
`;

export const glowFragmentShader = /* glsl */ `
  precision mediump float;
  uniform float uTime;

  varying vec2 vUv;
  varying vec3 vColor;
  varying float vActivity;
  varying float vSeverity;
  varying float vSelected;
  varying float vAlive;
  varying float vDim;

  void main() {
    float d = length(vUv - 0.5) * 2.0;
    if (d > 1.0) discard;
    // Two-lobe aura: a tight bright core plus a wide soft halo, summed. Reads as a
    // real bloom seed with a gentle outer glow rather than one hard-edged blob.
    float core = smoothstep(1.0, 0.0, d);
    core *= core * core;                       // tight, punchy centre
    float halo = smoothstep(1.0, 0.0, d);      // wide, soft skirt
    float a = core + halo * 0.35;
    float pulse = 0.7 + 0.3 * sin(uTime * 2.0 + vActivity * 6.2831);
    float intensity = (0.22 + 0.7 * vActivity) * pulse + 0.5 * vSelected;
    // Severity (G1.3): the halo warms with the node's risk grade, so a flagged
    // node's whole aura — not just its rim — reads warning.
    vec3 col = mix(vColor, vec3(1.0, 0.30, 0.16), vSeverity * 0.55);
    gl_FragColor = vec4(col * intensity * a * mix(0.2, 1.0, vAlive) * vDim, a * vDim);
  }
`;
