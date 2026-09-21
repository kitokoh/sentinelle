import { mkdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { expect, test } from '@playwright/test'

/**
 * Captures d'écran et GIF de démonstration (v0.7, issue #24).
 *
 * Ce spec n'est **pas** un test : il produit les images du README. Il est donc
 * rangé à part (`e2e/capture.spec.ts`) et jamais lancé par la CI, où il
 * échouerait faute de données de démonstration.
 *
 *   ./scripts/capture-screenshots.sh
 *
 * Les captures sont prises contre la vraie interface, alimentée par
 * `backend/seed_demo.py`. Aucune image n'est fabriquée : ce que le README montre
 * est ce que la plateforme affiche.
 */

const OUTPUT = process.env.CAPTURE_DIR ?? resolve(process.cwd(), '..', 'docs', 'assets')
const FRAMES = process.env.CAPTURE_FRAMES ?? resolve(process.cwd(), '.playwright-frames')
const EMAIL = process.env.E2E_EMAIL ?? 'admin@sentinelle.local'
const PASSWORD = process.env.E2E_PASSWORD ?? 'Sentinelle2026!'

let frameIndex = 0

/** Une image de plus pour le GIF. */
async function frame(page: import('@playwright/test').Page, label: string) {
  frameIndex += 1
  const name = `${String(frameIndex).padStart(2, '0')}-${label}.png`
  await page.screenshot({ path: join(FRAMES, name) })
}

async function capture(page: import('@playwright/test').Page, name: string) {
  await page.screenshot({ path: join(OUTPUT, `${name}.png`), fullPage: false })
}

test.describe('Captures de démonstration', () => {
  test('produit les 3 captures et les images du GIF', async ({ page }) => {
    mkdirSync(OUTPUT, { recursive: true })
    mkdirSync(FRAMES, { recursive: true })

    // --- Connexion (début du GIF) -------------------------------------------
    await page.goto('/login')
    await expect(page.getByRole('heading', { name: 'SENTINELLE' })).toBeVisible()
    await frame(page, 'login')

    await page.getByLabel('Adresse e-mail').fill(EMAIL)
    await page.getByLabel('Mot de passe').fill(PASSWORD)
    await frame(page, 'login-rempli')
    await page.getByRole('button', { name: 'Se connecter' }).click()

    // --- Tableau de bord ----------------------------------------------------
    await expect(page.getByRole('heading', { name: 'Tableau de bord', level: 1 })).toBeVisible()
    // Les compteurs viennent d'une requête : on laisse le rendu se stabiliser
    // pour ne pas capturer un « 0 » transitoire.
    await expect(page.locator('.panel').filter({ hasText: 'Cibles' }).first()).toBeVisible()
    await page.waitForTimeout(600)
    await capture(page, 'dashboard')
    await frame(page, 'dashboard')

    // --- Cibles -------------------------------------------------------------
    await page.getByRole('link', { name: 'Cibles' }).click()
    await expect(page.getByRole('heading', { name: 'Cibles', level: 1 })).toBeVisible()
    await expect(page.getByText('Serveur intranet RH').first()).toBeVisible()
    await page.waitForTimeout(400)
    await capture(page, 'cibles')
    await frame(page, 'cibles')

    // --- Détail d'un scan terminé (avec constats) ---------------------------
    await page.getByRole('link', { name: 'Scans' }).click()
    await expect(page.getByRole('heading', { name: 'Scans', level: 1 })).toBeVisible()
    await frame(page, 'scans')

    const completed = page.getByRole('row', { name: /Terminé/ }).first()
    await completed.getByTitle('Voir le détail').click()
    await expect(page.getByRole('heading', { name: /Scan #/, level: 1 })).toBeVisible()
    await expect(page.getByText('Constats').first()).toBeVisible()
    await page.waitForTimeout(400)
    await capture(page, 'scan')
    await frame(page, 'scan')

    // --- Alertes ------------------------------------------------------------
    await page.getByRole('link', { name: 'Alertes' }).click()
    await expect(page.getByRole('heading', { name: 'Alertes', level: 1 })).toBeVisible()
    await expect(page.getByText('port_scan').first()).toBeVisible()
    await page.waitForTimeout(400)
    await capture(page, 'alertes')
    await frame(page, 'alertes')

    // --- Renseignement ------------------------------------------------------
    await page.getByRole('link', { name: 'Renseignement' }).click()
    await expect(page.getByRole('heading', { name: 'Renseignement', level: 1 })).toBeVisible()
    await page.waitForTimeout(900) // la carte est chargée en différé
    await capture(page, 'renseignement')
    await frame(page, 'renseignement')

    // --- Journal d'audit (administrateur) -----------------------------------
    await page.getByRole('link', { name: "Journal d'audit" }).click()
    await expect(page.getByRole('heading', { name: "Journal d'audit", level: 1 })).toBeVisible()
    await page.waitForTimeout(400)
    await capture(page, 'journal')
    await frame(page, 'journal')
  })
})
