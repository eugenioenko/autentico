import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/admin/",
  server: {
    proxy: {
      "/oauth2": "http://localhost:9999",
      "/.well-known": "http://localhost:9999",
    },
  },
});
