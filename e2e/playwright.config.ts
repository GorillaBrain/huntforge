import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: '.',
  testMatch: '*.spec.ts',
  timeout: 60_000,
  workers: 1,
  use: { baseURL: process.env.BASE_URL ?? 'http://localhost:5173', viewport: { width: 1440, height: 900 } },
})
