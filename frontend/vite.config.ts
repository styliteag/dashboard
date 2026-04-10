import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev: Vite serves the SPA on :5173 and proxies /api to the backend container.
// In prod: the built static files are served by nginx behind Caddy; /api is proxied by Caddy.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VITE_BACKEND_URL ?? "http://backend:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
