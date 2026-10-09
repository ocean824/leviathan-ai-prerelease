import { fileURLToPath } from 'node:url'
import { defineConfig } from '../ui/node_modules/vitest/dist/config.js'
import react from '../ui/node_modules/@vitejs/plugin-react/dist/index.js'

const adminRoot = fileURLToPath(new URL('..', import.meta.url))

export default defineConfig({
  root: adminRoot,
  plugins: [react()],
  resolve: {
    alias: {
      '@testing-library/react': fileURLToPath(new URL('../ui/node_modules/@testing-library/react/dist/index.js', import.meta.url)),
      'react/jsx-dev-runtime': fileURLToPath(new URL('../ui/node_modules/react/jsx-dev-runtime.js', import.meta.url)),
      'react/jsx-runtime': fileURLToPath(new URL('../ui/node_modules/react/jsx-runtime.js', import.meta.url)),
      react: fileURLToPath(new URL('../ui/node_modules/react/index.js', import.meta.url)),
      vitest: fileURLToPath(new URL('../ui/node_modules/vitest/dist/index.js', import.meta.url)),
    },
  },
  define: { __ADMIN_WORKER_ORIGIN__: JSON.stringify('https://licensing-worker.invalid') },
  test: {
    environment: 'jsdom',
    setupFiles: ['ui/src/test/setup.ts'],
    include: ['qa/admin_app_mutation.test.tsx'],
    css: true,
    fileParallelism: false,
    maxWorkers: 1,
  },
})
