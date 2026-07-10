// Marine-snow particle layers (ROADMAP B2). The prototype's 3-layer vertex-shader
// drift field (SALVAGE.md), re-cast for the deep sea: slower fall, sparser, finer
// — flecks of organic detritus catching the bioluminescence as they sink. Each
// layer drifts at its own speed/scale for parallax depth.
//
// All motion lives in the vertex shader (a wrapped downward drift plus a lazy
// lateral sway); the CPU only sets a per-frame time uniform, so the field costs
// effectively nothing on the main thread (PITFALLS B1: no per-frame React state,
// no per-particle CPU work).

export const snowVertexShader = /* glsl */ `
  uniform float uTime;
  uniform float uFallSpeed;
  uniform float uSwayAmp;
  uniform float uHalfHeight;  // half the wrap volume height
  uniform float uSize;
  uniform float uMotion;      // 0 freezes drift (reduced-motion)
  uniform float uPixelRatio;

  attribute float aSeed;      // per-particle phase, 0..1

  varying float vSeed;

  void main(){
    vSeed = aSeed;
    vec3 pos = position;

    float t = uTime * uMotion;
    // Sink and wrap: subtract drift, modulo the column height so particles that
    // fall off the bottom reappear at the top — an endless gentle snowfall.
    float fall = t * uFallSpeed * (0.6 + 0.8 * aSeed);
    float y = pos.y - fall;
    y = mod(y + uHalfHeight, uHalfHeight * 2.0) - uHalfHeight;
    pos.y = y;

    // Lazy lateral sway, decorrelated per particle by its seed.
    float phase = aSeed * 6.2831853;
    pos.x += sin(t * 0.15 + phase) * uSwayAmp;
    pos.z += cos(t * 0.12 + phase * 1.7) * uSwayAmp;

    vec4 mv = modelViewMatrix * vec4(pos, 1.0);
    // Size attenuates with distance; varied per particle for a finer dusting.
    gl_PointSize = uSize * uPixelRatio * (0.5 + aSeed) / max(-mv.z, 1.0);
    gl_Position = projectionMatrix * mv;
  }
`;

export const snowFragmentShader = /* glsl */ `
  precision mediump float;
  uniform vec3 uColor;
  uniform float uOpacity;
  varying float vSeed;

  void main(){
    // Soft round flake: radial falloff from the point centre.
    vec2 d = gl_PointCoord - 0.5;
    float r = dot(d, d);
    if (r > 0.25) discard;
    float alpha = smoothstep(0.25, 0.0, r) * uOpacity * (0.4 + 0.6 * vSeed);
    gl_FragColor = vec4(uColor, alpha);
  }
`;
