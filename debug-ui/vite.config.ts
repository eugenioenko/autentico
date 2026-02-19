import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/oauth2": "http://localhost:9999",
      "/.well-known": "http://localhost:9999",
    },
  },
});
