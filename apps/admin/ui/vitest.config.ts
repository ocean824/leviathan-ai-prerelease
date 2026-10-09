import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  define: { __ADMIN_WORKER_ORIGIN__: JSON.stringify('https://licensing-worker.invalid') },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: true,
    fileParallelism: false,
    maxWorkers: 1,
  },
})
