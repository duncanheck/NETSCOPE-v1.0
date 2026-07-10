// Tendril shaders (ROADMAP B4). Each connection is a luminous thread from the host
// core to its endpoint node: a camera-facing ribbon whose path sways on 3D noise,
// whose width tracks activity, and along which bright "traffic" motes travel.
//
// The PITFALLS B4 prefire is to ship the GPU path directly — no per-frame CPU
// ribbon rebuild. So all of it lives in the vertex shader: the base geometry is a
// flat strip carrying only its along-parameter `t` (in position.x) and cross-side
// `±1` (in position.y); the real 3D curve, the noise sway, and the billboarded
// width are computed here per vertex. Per-tendril data (endpoint, colour, activity)
// rides as instanced attributes, so the whole field is one draw call.

import { snoise3 } from "./noise";

export const tendrilVertexShader = /* glsl */ `
  uniform float uTime;
  uniform vec3 uStart;     // the host core — every tendril begins here

  attribute vec3 aEnd;     // endpoint node position
  attribute vec3 aColor;
  attribute float aActivity;
  attribute float aPhase;
  attribute float aAlive;
  attribute float aSeverity;
  attribute float aSelected;
  attribute float aDim;

  varying float vT;
  varying float vSide;
  varying vec3 vColor;
  varying float vActivity;
  varying float vAlive;
  varying float vSeverity;
  varying float vSelected;
  varying float vDim;

  ${snoise3}

  // A point on the swaying curve at along-parameter t ∈ [0,1].
  vec3 curvePoint(float t) {
    vec3 base = mix(uStart, aEnd, t);
    vec3 dir = aEnd - uStart;
    float len = max(length(dir), 0.001);
    dir /= len;
    // Build a perpendicular basis to displace within.
    vec3 up = abs(dir.y) < 0.99 ? vec3(0.0, 1.0, 0.0) : vec3(1.0, 0.0, 0.0);
    vec3 perp1 = normalize(cross(dir, up));
    vec3 perp2 = normalize(cross(dir, perp1));
    // Envelope pins both ends and bulges the middle; amplitude grows with activity.
    float env = sin(t * 3.14159265);
    float amp = (0.25 + 0.6 * aActivity) * min(len * 0.18, 1.2);
    float n1 = snoise(vec3(t * 2.0, uTime * 0.4 + aPhase, 0.0));
    float n2 = snoise(vec3(t * 2.0 + 5.0, uTime * 0.35 + aPhase, 10.0));
    return base + (perp1 * n1 + perp2 * n2) * env * amp;
  }

  void main() {
    float t = position.x;     // along the tendril
    float side = position.y;  // -1 / +1 cross-section

    // Curve point and a neighbour, for the screen-space tangent.
    float dt = 0.02;
    float tN = t < 1.0 ? min(t + dt, 1.0) : t - dt;
    vec4 pv = modelViewMatrix * vec4(curvePoint(t), 1.0);
    vec4 pvN = modelViewMatrix * vec4(curvePoint(tN), 1.0);

    vec2 tangent = pvN.xy - pv.xy;
    float tl = length(tangent);
    vec2 sideDir = tl > 1e-5 ? vec2(-tangent.y, tangent.x) / tl : vec2(1.0, 0.0);

    // Taper: thin where it leaves the host core, blooming toward the endpoint —
    // the thread reads as reaching out and latching on, not a uniform pipe.
    float taper = 0.35 + 0.9 * t;
    float halfWidth = (0.02 + 0.10 * aActivity) * taper * (1.0 + 0.6 * aSelected);
    pv.xy += sideDir * side * halfWidth;

    vT = t;
    vSide = side;
    vColor = aColor;
    vActivity = aActivity;
    vAlive = aAlive;
    vSeverity = aSeverity;
    vSelected = aSelected;
    vDim = aDim;
    gl_Position = projectionMatrix * pv;
  }
`;

export const tendrilFragmentShader = /* glsl */ `
  precision highp float;

  uniform float uTime;

  varying float vT;
  varying float vSide;
  varying vec3 vColor;
  varying float vActivity;
  varying float vAlive;
  varying float vSeverity;
  varying float vSelected;
  varying float vDim;

  void main() {
    // Soft cross-section: a bright thin spine with a softer sheath around it —
    // the extra cross term draws a crisper filament than a plain square.
    float cross = 1.0 - abs(vSide);
    float core = cross * cross * (0.6 + 0.4 * cross);

    // Steady glow along the thread, brightening toward the endpoint so the eye is
    // drawn out to the node rather than back into the host tangle.
    float base = (0.05 + 0.20 * vActivity) * (0.6 + 0.5 * vT);

    // Traffic motes: bright gaussians travelling from core → endpoint, faster and
    // brighter with activity. Three staggered motes read as a steadier stream,
    // plus a softer head-mote pooling at the endpoint so arrival registers.
    float speed = 0.25 + 0.6 * vActivity;
    float motes = 3.0;
    float m = fract(vT * motes - uTime * speed);
    float mote = exp(-pow(m / 0.10, 2.0)) * (0.4 + 1.7 * vActivity);
    mote += exp(-pow((vT - 1.0) / 0.16, 2.0)) * (0.25 + 0.9 * vActivity)
            * (0.5 + 0.5 * sin(uTime * 3.0 + vT * 6.2831));

    float intensity = base + mote + 0.4 * vSelected;
    // Warm slightly toward the head for depth, then (G1.3) bend a risky flow's
    // thread toward the warning hue so the path to a flagged endpoint stands out.
    vec3 tone = mix(vColor, mix(vColor, vec3(1.0), 0.22), vT);
    vec3 col = mix(tone, vec3(1.0, 0.30, 0.16), vSeverity * 0.5) * intensity * core;
    float alpha = core * (0.5 + 0.5 * vActivity) * mix(0.15, 1.0, vAlive) * vDim;
    // Premultiplied for additive blending (SRC_ALPHA, ONE).
    gl_FragColor = vec4(col * mix(0.25, 1.0, vAlive) * vDim, alpha);
  }
`;
