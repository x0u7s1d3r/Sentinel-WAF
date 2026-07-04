import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// En développement (npm run dev), les appels /_sentinel sont relayés vers la
// passerelle. En production, c'est nginx qui s'en charge (voir nginx.conf).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/_sentinel': 'http://127.0.0.1:8080' },
  },
})
