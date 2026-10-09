import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const fallbackWorkerOrigin = 'https://licensing-worker.invalid'

function configuredWorkerOrigin(): string {
  const value = process.env.VITE_ADMIN_WORKER_ORIGIN ?? fallbackWorkerOrigin
  const parsed = new URL(value)
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error('VITE_ADMIN_WORKER_ORIGIN must be an HTTPS origin')
  }
  return parsed.origin
}

export default defineConfig({
  plugins: [react()],
  define: {
    __ADMIN_WORKER_ORIGIN__: JSON.stringify(configuredWorkerOrigin()),
  },
  server: { host: '127.0.0.1', port: 1420, strictPort: true },
})
