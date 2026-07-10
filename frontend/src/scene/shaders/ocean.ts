// The deep-ocean environment shader (ROADMAP B2). A domain-warped fBm sampled
// per-pixel paints a dark water column: near-black blue-greens, surface light
// attenuating downward into the deep, with a slow vertical drift so it reads as a
// moving current rather than a static sky. This is the prototype's nebula
// (Ashima simplex + multi-octave fBm + two-level domain warp) re-art-directed to
// the bioluminescent deep-sea palette (SALVAGE.md).
//
// It is rendered to a HALF-RESOLUTION render target and composited up (see
// DeepOcean.tsx) — fBm+warp is the most expensive thing on screen, and at the
// murk we're drawing the bilinear upscale is invisible. The octave count is gated
// by a startup GPU micro-benchmark (capability.ts), never by user-agent sniffing
// (PITFALLS B2): the `OCTAVES` define is injected at material-build time.

// Fullscreen pass: the geometry is a [-1,1] quad, so positions are already in
// clip space and no camera matrices are needed.
export const oceanVertexShader = /* glsl */ `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = vec4(position.xy, 0.0, 1.0);
  }
`;

export const oceanFragmentShader = /* glsl */ `
  precision highp float;

  varying vec2 vUv;
  uniform float uTime;
  uniform vec2  uResolution;
  uniform float uMotion;   // 0 freezes drift (reduced-motion); 1 full

  // Octave count is injected as a define by the capability tier.
  #ifndef OCTAVES
  #define OCTAVES 5
  #endif

  // --- Ashima 2D simplex noise (snoise) --------------------------------------
  vec3 mod289(vec3 x){ return x - floor(x * (1.0 / 289.0)) * 289.0; }
  vec2 mod289(vec2 x){ return x - floor(x * (1.0 / 289.0)) * 289.0; }
  vec3 permute(vec3 x){ return mod289(((x * 34.0) + 1.0) * x); }
  float snoise(vec2 v){
    const vec4 C = vec4(0.211324865405187, 0.366025403784439,
                       -0.577350269189626, 0.024390243902439);
    vec2 i  = floor(v + dot(v, C.yy));
    vec2 x0 = v -   i + dot(i, C.xx);
    vec2 i1 = (x0.x > x0.y) ? vec2(1.0, 0.0) : vec2(0.0, 1.0);
    vec4 x12 = x0.xyxy + C.xxzz;
    x12.xy -= i1;
    i = mod289(i);
    vec3 p = permute(permute(i.y + vec3(0.0, i1.y, 1.0))
                            + i.x + vec3(0.0, i1.x, 1.0));
    vec3 m = max(0.5 - vec3(dot(x0, x0), dot(x12.xy, x12.xy),
                            dot(x12.zw, x12.zw)), 0.0);
    m = m * m; m = m * m;
    vec3 x  = 2.0 * fract(p * C.www) - 1.0;
    vec3 h  = abs(x) - 0.5;
    vec3 ox = floor(x + 0.5);
    vec3 a0 = x - ox;
    m *= 1.79284291400159 - 0.85373472095314 * (a0 * a0 + h * h);
    vec3 g;
    g.x  = a0.x * x0.x + h.x * x0.y;
    g.yz = a0.yz * x12.xz + h.yz * x12.yw;
    return 130.0 * dot(m, g);
  }

  // Fractal Brownian motion — OCTAVES of snoise, halving amplitude/doubling freq.
  float fbm(vec2 p){
    float v = 0.0;
    float a = 0.5;
    for (int i = 0; i < OCTAVES; i++){
      v += a * snoise(p);
      p *= 2.0;
      a *= 0.5;
    }
    return v;
  }

  void main(){
    // Aspect-correct coords; the slow upward drift is the water column moving.
    float aspect = uResolution.x / max(uResolution.y, 1.0);
    vec2 p = vec2(vUv.x * aspect, vUv.y) * 3.0;
    float t = uTime * 0.05 * uMotion;
    p.y -= t; // current rises through the column

    // Two-level domain warp (IQ): fBm whose input is itself displaced by fBm.
    vec2 q = vec2(fbm(p + vec2(0.0, 0.3 * t)),
                  fbm(p + vec2(5.2, 1.3)));
    vec2 r = vec2(fbm(p + 4.0 * q + vec2(1.7, 9.2)),
                  fbm(p + 4.0 * q + vec2(8.3, 2.8)));
    float n = fbm(p + 4.0 * r);

    // Murk: a tight remap keeps the field mostly dark, with rare brighter veils.
    float veil = smoothstep(-0.35, 0.85, n);

    // Deep-sea palette — near-black blue-greens.
    vec3 deep = vec3(0.004, 0.016, 0.024);
    vec3 mid  = vec3(0.010, 0.055, 0.070);
    vec3 water = mix(deep, mid, veil);

    // Surface light attenuating with depth: brighter at the top (vUv.y → 1),
    // falling to near-black at the bottom of the column.
    float depthLight = smoothstep(0.0, 1.0, vUv.y);
    water += vec3(0.020, 0.085, 0.095) * depthLight * depthLight * (0.25 + 0.5 * veil);

    // Faint cold caustic shimmer riding the warp near the surface.
    float shimmer = max(length(r) - 0.8, 0.0) * depthLight;
    water += vec3(0.02, 0.06, 0.07) * shimmer;

    gl_FragColor = vec4(water, 1.0);
  }
`;

// The composite pass: sample the half-res ocean and draw it full-screen, with a
// gentle vignette to sink the edges into the deep. Bilinear upscaling of the RT
// is the documented half-res quality/cost trade — soft, which murk wants anyway.
export const compositeVertexShader = /* glsl */ `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = vec4(position.xy, 0.0, 1.0);
  }
`;

export const compositeFragmentShader = /* glsl */ `
  precision highp float;
  varying vec2 vUv;
  uniform sampler2D uScene;
  void main(){
    vec3 col = texture2D(uScene, vUv).rgb;
    // Radial vignette — darken toward the edges for a sense of enclosing depth.
    vec2 d = vUv - 0.5;
    float vig = smoothstep(0.95, 0.35, dot(d, d) * 2.6);
    gl_FragColor = vec4(col * vig, 1.0);
  }
`;
