/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Which transport the app boots with: "mock" (default) or "websocket". */
  readonly VITE_TRANSPORT?: "mock" | "websocket";
  /** Override the agent WebSocket URL (default ws://127.0.0.1:8787). */
  readonly VITE_AGENT_URL?: string;
  /** Wire content encoding: "json" (default) or "msgpack" (A5). */
  readonly VITE_WIRE_ENCODING?: "json" | "msgpack";
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
