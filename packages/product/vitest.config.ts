import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'jsdom',
    include: ['shared/**/*.spec.ts', 'entities/**/*.spec.ts', 'widgets/**/*.spec.ts'],
    globals: true,
  },
  resolve: {
    alias: {
      '@runne/product': resolve(__dirname, '.'),
    },
  },
})
