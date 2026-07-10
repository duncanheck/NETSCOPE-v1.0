// Relationship-edge shaders. An edge is a faint luminous link drawn directly between
// two endpoint nodes that share a relationship key (same process / org / country) —
// the secondary graph structure on top of the host→endpoint tendrils. Like the
// tendrils it is one instanced, billboarded ribbon with no per-frame CPU rebuild:
// the two endpoints (aStart, aEnd) ride as instanced attributes and the camera-facing
// width + a gentle directional shimmer are built in the vertex/fragment shaders.
//
// Edges read as a quieter, thinner thread than the tendrils so the host star stays
// the primary read and the relationship mesh is a legible undertone, not noise.

export const edgeVertexShader = /* glsl */ `
  attribute vec3 aStart;
  attribute vec3 aEnd;
  attribute vec3 aColor;
  attribute float aDim;     // focus dimming: 1.0 lit, <1.0 backgrounded

  varying float vT;
  varying float vSide;
  varying vec3 vColor;
  varying float vDim;

  void main() {
    float t = position.x;     // along the edge [0,1]
    float side = position.y;  // -1 / +1 cross-section

    float dt = 0.04;
    float tN = t < 1.0 ? min(t + dt, 1.0) : t - dt;
    vec4 pv = modelViewMatrix * vec4(mix(aStart, aEnd, t), 1.0);
    vec4 pvN = modelViewMatrix * vec4(mix(aStart, aEnd, tN), 1.0);

    vec2 tangent = pvN.xy - pv.xy;
    float tl = length(tangent);
    vec2 sideDir = tl > 1e-5 ? vec2(-tangent.y, tangent.x) / tl : vec2(1.0, 0.0);

    // Thin, slightly bowed-out at the middle so parallel edges don't z-fight to a line.
    float halfWidth = 0.018 * (0.6 + 0.8 * sin(t * 3.14159265));
    pv.xy += sideDir * side * halfWidth;

    vT = t;
    vSide = side;
    vColor = aColor;
    vDim = aDim;
    gl_Position = projectionMatrix * pv;
  }
`;

export const edgeFragmentShader = /* glsl */ `
  precision highp float;

  uniform float uTime;

  varying float vT;
  varying float vSide;
  varying vec3 vColor;
  varying float vDim;

  void main() {
    float cross = 1.0 - abs(vSide);
    float core = cross * cross;

    // A slow shimmer travelling along the link hints at the shared relationship
    // without competing with the tendrils' brighter traffic motes.
    float flow = 0.5 + 0.5 * sin(vT * 12.0 - uTime * 1.6);
    float intensity = 0.10 + 0.18 * flow;

    vec3 col = vColor * intensity * core * vDim;
    float alpha = core * 0.5 * vDim;
    gl_FragColor = vec4(col, alpha);
  }
`;
