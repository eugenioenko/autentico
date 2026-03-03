import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  base: "/account/",
  server: {
    proxy: {
      '/oauth2': 'http://localhost:9999',
      '/.well-known': 'http://localhost:9999',
      '/account/api': 'http://localhost:9999',
    },
  },
})
