import { defineConfig } from 'vite'
import { dirname, resolve } from 'node:path'
import react from '@vitejs/plugin-react'
import tailwindcss from "@tailwindcss/vite";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(),tailwindcss()],
  server: {
    host: true,      // same as 0.0.0.0
    port: 5173,
    strictPort: true,
    // No CORS: the charger only answers same-origin requests. In `npm run dev` the API
    // paths are proxied to the Pi (VITE_BACKEND, default http://openeo.local) so the
    // browser still sees ONE origin and the login cookie works.
    proxy: Object.fromEntries(
      ["/login", "/logout", "/health", "/auth", "/change_password", "/api_token", "/api", "/metrics",
       "/getstatus", "/getconfig", "/get_user_settings", "/getsessiondata", "/getchartdata",
       "/setsettings", "/update", "/restart", "/debugdata"].map((p) => [
        p, { target: process.env.VITE_BACKEND || "http://openeo.local", changeOrigin: false },
      ])
    ),
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/__tests__/setup.js"],
    include: ["src/__tests__/**/*.test.{js,jsx}"],
  },
  build: {
    rollupOptions: {
 //     input: {
 //       main: './index.html',
 //     },
    },
  },
})


