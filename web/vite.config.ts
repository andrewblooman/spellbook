import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// API lives at the FastAPI root (/findings, /runs, /attack-paths, ...). In dev the
// SPA runs on :5173 and proxies those to the control plane on :8000. In prod the
// SPA is served by FastAPI same-origin, so no proxy is used. Hash routing keeps UI
// routes (/#/...) from ever colliding with API paths.
const target = "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: {
      "/findings": { target, changeOrigin: true },
      "/runs": { target, changeOrigin: true },
      "/attack-paths": { target, changeOrigin: true },
      "/authorizations": { target, changeOrigin: true },
      "/wiz": { target, changeOrigin: true },
    },
  },
});
