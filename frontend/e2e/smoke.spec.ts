import { expect, test } from '@playwright/test'

/**
 * Smoke E2E — connexion → cible → scan → export (v0.7, issue #22).
 *
 * Ce que ce test couvre, et ce qu'il ne couvre pas :
 *
 * - il vérifie que **les couches tiennent ensemble** : le front parle à l'API, le
 *   garde-fou de périmètre laisse passer une cible interne, un scan se crée, et
 *   l'export produit un fichier. C'est un test de plomberie, pas de fonction.
 * - il ne vérifie **pas** l'exécution du scan : le worker n'est pas démarré (voir
 *   `.github/workflows/ci.yml`). Ce qu'un scan produit réellement est couvert par
 *   `backend/tests/test_worker.py`, avec les scanners simulés — plus rapide et
 *   déterministe qu'un nmap sur une cible qui n'existe pas.
 *
 * Les sélecteurs sont volontairement ancrés sur le texte visible et les `label`
 * associés : un sélecteur CSS sur une classe Tailwind casserait à la première
 * retouche graphique, sans rien dire d'utile.
 */

const EMAIL = process.env.E2E_EMAIL ?? 'admin@sentinelle.local'
const PASSWORD = process.env.E2E_PASSWORD ?? 'Sentinelle2026!'

// Plage RFC 5737 : une valeur par exécution, pour que rejouer le test ne bute pas
// sur la cible créée par la fois précédente.
const TARGET_VALUE = `10.20.30.${Math.floor(Math.random() * 200) + 40}`
const TARGET_NAME = `Smoke ${Date.now()}`

test.describe('Parcours nominal', () => {
  test('connexion → cible → scan → export', async ({ page }) => {
    // --- 1. Connexion -------------------------------------------------------
    await page.goto('/login')
    await expect(page.getByRole('heading', { name: 'SENTINELLE' })).toBeVisible()

    await page.getByLabel('Adresse e-mail').fill(EMAIL)
    await page.getByLabel('Mot de passe').fill(PASSWORD)
    await page.getByRole('button', { name: 'Se connecter' }).click()

    // Le tableau de bord est la preuve que le jeton a été accepté et que /auth/me
    // a répondu : sans utilisateur résolu, ce titre ne s'affiche pas.
    await expect(page.getByRole('heading', { name: 'Tableau de bord', level: 1 })).toBeVisible()

    // --- 2. Déclaration d'une cible ------------------------------------------
    await page.getByRole('link', { name: 'Cibles' }).click()
    // `level: 1` cible le titre de page : « Cibles » apparaît aussi en titre de
    // panneau, et un sélecteur ambigu est la première cause de test instable.
    await expect(page.getByRole('heading', { name: 'Cibles', level: 1 })).toBeVisible()

    await page.locator('#target-name').fill(TARGET_NAME)
    await page.locator('#target-value').fill(TARGET_VALUE)
    await page.locator('#target-kind').selectOption('ip')
    await page.getByRole('button', { name: 'Ajouter la cible' }).click()

    const targetRow = page.getByRole('row', { name: new RegExp(TARGET_VALUE) })
    await expect(targetRow).toBeVisible()
    // Le garde-fou de périmètre a laissé passer une adresse privée : c'est le
    // comportement attendu, et c'est ce que ce test doit empêcher de régresser.
    await expect(targetRow.getByText('Autorisée')).toBeVisible()

    // --- 3. Lancement d'un scan ---------------------------------------------
    await page.getByRole('link', { name: 'Scans' }).click()
    await expect(page.getByRole('heading', { name: 'Scans', level: 1 })).toBeVisible()

    await page.locator('#scan-target').selectOption({ label: `${TARGET_NAME} (${TARGET_VALUE})` })
    await page.getByRole('button', { name: 'Lancer le scan' }).click()

    const scanRow = page.getByRole('row', { name: new RegExp(TARGET_VALUE) })
    await expect(scanRow).toBeVisible()
    // Le statut dépend de l'environnement : avec une file et un worker le scan
    // reste « en attente » puis s'exécute, sans eux l'API le marque en échec avec
    // la raison. Ce test vérifie la plomberie (la demande est passée, une ligne
    // existe) ; l'exécution d'un scan est couverte par les tests backend, avec
    // les scanners simulés — plus rapide et déterministe qu'un nmap réel.
    await expect(scanRow.getByText(/En attente|En cours|Terminé|Échec/)).toBeVisible()

    // --- 4. Export des constats ---------------------------------------------
    await scanRow.getByTitle('Voir le détail').click()
    await expect(page.getByRole('heading', { name: /Scan #/, level: 1 })).toBeVisible()

    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: 'Exporter CSV' }).click(),
    ])
    expect(download.suggestedFilename()).toMatch(/^scan_\d+_findings\.csv$/)

    // Le fichier est bien un CSV, même vide de constats : en-tête seul.
    const stream = await download.createReadStream()
    const content = await new Promise<string>((resolve, reject) => {
      let buffer = ''
      stream.on('data', (chunk) => (buffer += chunk.toString()))
      stream.on('end', () => resolve(buffer))
      stream.on('error', reject)
    })
    // Le module `csv` de Python termine ses lignes par CRLF : on normalise avant
    // de comparer, sinon le test échoue sur un détail de plateforme.
    const header = content.split(/\r?\n/)[0]
    expect(header).toBe('source,port,protocol,service,version,severity,detail')
  })

  test('la cible hors périmètre est refusée', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Adresse e-mail').fill(EMAIL)
    await page.getByLabel('Mot de passe').fill(PASSWORD)
    await page.getByRole('button', { name: 'Se connecter' }).click()
    await expect(page.getByRole('heading', { name: 'Tableau de bord', level: 1 })).toBeVisible()

    await page.getByRole('link', { name: 'Cibles' }).click()
    await page.locator('#target-name').fill(`Refusée ${Date.now()}`)
    // Adresse publique, sans référence d'autorisation : le garde-fou doit refuser.
    await page.locator('#target-value').fill('93.184.216.34')
    await page.locator('#target-kind').selectOption('ip')
    await page.getByRole('button', { name: 'Ajouter la cible' }).click()

    await expect(page.getByText('Refusée').first()).toBeVisible()
  })

  test('les pages de lecture répondent', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Adresse e-mail').fill(EMAIL)
    await page.getByLabel('Mot de passe').fill(PASSWORD)
    await page.getByRole('button', { name: 'Se connecter' }).click()
    await expect(page.getByRole('heading', { name: 'Tableau de bord', level: 1 })).toBeVisible()

    // Chaque entrée de la barre latérale doit mener à un écran fonctionnel : une
    // page qui plante est un écran blanc, et un écran blanc ne se voit pas en CI.
    for (const section of ['Alertes', 'Renseignement', 'Rapports', 'Doctrine']) {
      await page.getByRole('link', { name: section }).click()
      await expect(page.getByRole('heading', { name: section, level: 1 })).toBeVisible()
    }
  })
})
