/**
 * Test de charge — tableau de bord Sentinelle (issue #20).
 *
 * Critère d'acceptation : « 100 req/s dashboard sans erreur ».
 *
 * POURQUOI LE TABLEAU DE BORD EST LE BON CANARI
 * ---------------------------------------------
 * `GET /api/dashboard/stats` est l'endpoint le plus coûteux et le plus
 * représentatif de la plateforme, pour trois raisons :
 *
 *  1. il agrège **quatre tables** (targets, scans, findings, alerts) avec des
 *     `COUNT(*)` filtrés par organisation, plus un `GROUP BY severity` et un
 *     `ORDER BY created_at DESC LIMIT 5` avec jointure. Une régression d'index
 *     ou une dérive de schéma s'y voit immédiatement, alors qu'un
 *     `GET /api/health` resterait vert en toutes circonstances ;
 *  2. c'est la **page d'accueil** : c'est la requête que tous les utilisateurs
 *     connectés lancent en même temps, notamment au moment d'un incident — donc
 *     exactement quand la plateforme doit tenir ;
 *  3. c'est une lecture (`viewer_required`) : la charger ne crée ni scan, ni
 *     alerte, ni ligne de journal d'audit. Un test de charge doit rester
 *     inoffensif sur les données, sinon il finit par fausser ce qu'il mesure.
 *
 * Ce que ce script ne fait PAS : aucun scan, aucune écriture, aucune cible
 * externe. Une seule requête mutante (l'authentification) a lieu, une fois,
 * dans `setup()`.
 *
 * Lancer uniquement contre une instance dont vous êtes responsable. Voir
 * deploy/load/README.md et SECURITY.md (cadre légal).
 */

import http from 'k6/http';
import { check, sleep } from 'k6';

// ---------------------------------------------------------------------------
// Paramètres — tout vient de l'environnement, aucun secret dans ce fichier.
// ---------------------------------------------------------------------------

const BASE_URL = (__ENV.SENTINELLE_BASE_URL || 'http://localhost:8000').replace(/\/+$/, '');
const EMAIL = __ENV.SENTINELLE_EMAIL;
const PASSWORD = __ENV.SENTINELLE_PASSWORD;

// Débit visé : la constante du critère d'acceptation est écrite en dur pour
// qu'elle se lise dans le code, et surchargeable pour explorer la limite de la
// plateforme sans modifier le script (SENTINELLE_TARGET_RPS=250).
const TARGET_RPS = Number(__ENV.SENTINELLE_TARGET_RPS || 100);

// 2 minutes : assez long pour que le plateau soit mesurable (on ignore les
// premières secondes de chauffe : pools de connexions, caches, JIT), assez
// court pour rester dans une CI ou une démo.
const DURATION = __ENV.SENTINELLE_DURATION || '2m';

export const options = {
  scenarios: {
    // Scénario de référence : 100 itérations par seconde, chacune un appel
    // `GET /api/dashboard/stats`. `constant-arrival-rate` (et non `constant-vus`)
    // est le seul exécuteur qui garantit une *cadence* : il ouvre le débit
    // demandé, et si la latence monte, k6 le signale via `dropped_iterations`
    // au lieu de rendre un test « vert » qui n'a en réalité pas tenu 100 req/s.
    dashboard: {
      executor: 'constant-arrival-rate',
      exec: 'dashboardStats',
      rate: TARGET_RPS,
      timeUnit: '1s',
      duration: DURATION,
      // ~100 rps x 0,5 s de latence p95 => 50 VU en régime nominal. On provisionne
      // le double : une petite oscillation de latence ne doit pas se traduire par
      // des itérations perdues (ce qui invaliderait la mesure).
      preAllocatedVUs: 100,
      maxVUs: 400,
    },
    // Exploration des autres lectures (cibles, scans, alertes, santé) à faible
    // débit : elles doivent tenir sous charge, mais leur mesure ne doit pas être
    // noyée dans celle du dashboard. Démarrage décalé pour laisser le plateau
    // du scénario principal s'établir.
    reads: {
      executor: 'constant-vus',
      exec: 'readEndpoints',
      vus: 3,
      duration: DURATION,
      startTime: '10s',
    },
  },

  thresholds: {
    // Critère d'acceptation #20 : « 100 req/s sans erreur ». 1 % de tolérance,
    // jamais 5 % : sur un dashboard de supervision, une requête perdue est une
    // décision prise à l'aveugle.
    http_req_failed: ['rate<0.01'],
    'http_req_failed{scenario:dashboard}': ['rate<0.01'],

    // Latence. 500 ms de p95 pour le dashboard : la requête fait quatre
    // agrégations ; au-delà d'une demi-seconde, l'interface paraît figée et la
    // plateforme n'est plus « temps réel ». 300 ms pour les lectures simples.
    // Ce sont des seuils de tenue d'une instance de démonstration, pas une
    // promesse de capacité (voir deploy/load/README.md § Limites).
    'http_req_duration{scenario:dashboard}': ['p(95)<500'],
    'http_req_duration{scenario:reads}': ['p(95)<300'],

    // Toutes les vérifications fonctionnelles (code HTTP, corps exploitable).
    checks: ['rate>0.99'],

    // Garde-fou d'honnêteté : si k6 n'a pas pu placer toutes les itérations
    // demandées, le débit réel est inférieur à la cible et le test est invalide,
    // même si tous les autres seuils sont verts.
    dropped_iterations: ['count==0'],
  },

  // Les percentiles utiles au rapport : la moyenne cache exactement ce qui nous
  // intéresse (la queue de distribution).
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],

  // Un test de charge qui parle dans le journal d'audit est identifiable.
  userAgent: 'k6-sentinelle-loadtest/1.0',
};

/**
 * Authentification, une seule fois pour toute la campagne.
 *
 * POURQUOI PAS DANS LA BOUCLE : `/api/auth/login` vérifie un mot de passe
 * bcrypt, coûteux *par construction*. Le mesurer 100 fois par seconde
 * reviendrait à mesurer le durcissement des mots de passe, et le résultat ne
 * dirait rien du dashboard — tout en noyant les journaux d'audit sous les
 * connexions. Le dashboard est le sujet du test, l'authentification n'en est
 * que le préalable.
 *
 * Le jeton JWT obtenu dure 60 minutes (JWT_EXPIRE_MINUTES) : compatible avec
 * les campagnes courtes de ce script.
 */
export function setup() {
  if (!EMAIL || !PASSWORD) {
    throw new Error(
      'SENTINELLE_EMAIL et SENTINELLE_PASSWORD sont requis. ' +
        'Amorcer une instance avec : docker compose exec api python seed.py',
    );
  }

  const response = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify({ email: EMAIL, password: PASSWORD }),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { endpoint: 'auth/login' },
    },
  );

  const authenticated = check(response, {
    'login: HTTP 200': (r) => r.status === 200,
    'login: jeton exploitable': (r) => typeof r.json('access_token') === 'string',
  });

  if (!authenticated) {
    throw new Error(
      `Authentification refusée (HTTP ${response.status}). Vérifier SENTINELLE_EMAIL / ` +
        'SENTINELLE_PASSWORD, et que l\'instance est amorcée (python seed.py).',
    );
  }

  return { token: response.json('access_token') };
}

/** En-têtes communs : un seul endroit où le jeton est injecté. */
function authorization(data) {
  return { Authorization: `Bearer ${data.token}` };
}

/**
 * Scénario principal : le tableau de bord.
 *
 * POURQUOI PAS DE sleep() ICI : avec un exécuteur à débit imposé, c'est k6 qui
 * cadence les itérations. Un `sleep()` ne ralentirait pas le test, il
 * immobiliserait les VU ; k6 compenserait alors en itérations non exécutées
 * (`dropped_iterations`), c'est-à-dire en débit réel *inférieur* à 100 req/s,
 * tout en affichant des latences flatteuses.
 */
export function dashboardStats(data) {
  const response = http.get(`${BASE_URL}/api/dashboard/stats`, {
    headers: authorization(data),
    tags: { endpoint: 'dashboard/stats' },
  });

  check(response, {
    'dashboard: HTTP 200': (r) => r.status === 200,
    // Un corps 200 mais vide serait une panne silencieuse : on vérifie que
    // l'agrégat est bien calculé, pas seulement que la route répond.
    'dashboard: charge utile exploitable': (r) => r.json('targets_count') !== undefined,
  });
}

/**
 * Scénario secondaire : les autres lectures de l'interface.
 *
 * Ici le `sleep()` a un sens : ce scénario doit rester à faible débit pour ne
 * pas brouiller la mesure du dashboard. Il vérifie que les pages « Cibles »,
 * « Scans », « Alertes » et la sonde de santé ne tombent pas pendant que le
 * dashboard est chargé.
 */
export function readEndpoints(data) {
  const endpoints = ['/api/targets', '/api/scans', '/api/alerts', '/api/health'];

  for (const endpoint of endpoints) {
    const response = http.get(`${BASE_URL}${endpoint}`, {
      headers: authorization(data),
      tags: { endpoint: endpoint },
    });
    check(response, {
      [`${endpoint}: HTTP 200`]: (r) => r.status === 200,
    });
  }

  sleep(1);
}
