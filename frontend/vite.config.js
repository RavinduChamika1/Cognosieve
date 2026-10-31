import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',
    // Prevent ZAP active scan payloads from being treated as valid Vite module requests
    allowedHosts: 'all',
    hmr: {
      // Use a separate port for HMR websocket so it's not confused with regular HTTP probes
      port: 3001,
      host: 'localhost',
    },
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      }
    }
  }
})

