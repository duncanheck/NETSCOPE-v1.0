import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies nothing — the agent's WebSocket is reached directly at
// ws://127.0.0.1:8787 (see src/transport). Tailnet reachability is milestone C3.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
});
