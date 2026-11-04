import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import yarcl from "@yarcl/react/vite";

export default defineConfig({
  plugins: [react(), yarcl({ config: "src/yarcl.config.ts", emitTokens: false })],
  base: "/admin/",
  resolve: {
    dedupe: ["react", "react-dom"],
  },
  server: {
    proxy: {
      "/admin/api": "http://localhost:9999",
      "/oauth2": "http://localhost:9999",
      "/.well-known": "http://localhost:9999",
    },
  },
});
