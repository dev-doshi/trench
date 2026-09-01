import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// Builds the SPA into ../dist, which aiohttp serves as static assets.
// Dev server proxies the API + WebSocket to a locally running trench.
export default defineConfig({
  plugins: [vue()],
  base: "/",
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    assetsDir: "assets",
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: 5199,
    proxy: {
      "/api": { target: "http://127.0.0.1:8089", changeOrigin: true, ws: true },
      "/metrics": "http://127.0.0.1:8089",
    },
  },
});
