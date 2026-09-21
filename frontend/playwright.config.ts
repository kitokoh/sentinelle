import { defineConfig, devices } from '@playwright/test'

/**
 * Configuration Playwright (v0.7, issues #22 et #24).
 *
 * Deux usages, un seul fichier :
 *
 * - **CI / E2E** : `npm run e2e`, contre la pile démarrée par la CI
 *   (`E2E_BASE_URL` pointe alors sur le service `web` de Docker Compose).
 * - **captures d'écran** : `npm run e2e:capture`, contre un serveur Vite local
 *   alimenté par `backend/seed_demo.py`.
 *
 * `workers: 1` et `fullyParallel: false` ne sont pas des pruderies : le scénario
 * crée une cible et lance un scan sur un compte partagé. Deux exécutions
 * concurrentes se marcheraient dessus, et un test qui échoue une fois sur trois
 * ne vaut rien.
 */
const baseURL = process.env.E2E_BASE_URL ?? 'http://localhost:5173'
const isCI = Boolean(process.env.CI)

export default defineConfig({
  testDir: './e2e',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: isCI ? 1 : 0,
  reporter: isCI ? [['github'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL,
    // Les artefacts d'échec sont la seule façon de comprendre un test rouge en
    // CI sans pouvoir le relancer : on les garde systématiquement.
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    actionTimeout: 15_000,
    locale: 'fr-FR',
    timezoneId: 'Europe/Paris',
    viewport: { width: 1440, height: 900 },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
  ],
})
