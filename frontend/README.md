# Sentinelle — Frontend

Interface « SOC / mission control » de la plateforme souveraine d'audit de sécurité
et de cyber-défense **Sentinelle**. UI sombre (slate-950 / slate-900, accents
cyan-400 / emerald-400, rouge pour les critiques), intégralement en français.

## Stack

- **Vite 5 + React 18 + TypeScript**
- **TailwindCSS v3** (config PostCSS classique)
- **react-router-dom v6** — routage + garde d'authentification
- **@tanstack/react-query v5** — données serveur, mutations, rafraîchissement périodique
- **axios** — instance `/api`, jeton Bearer (`localStorage: sentinelle_token`), redirection `/login` sur 401
- **lucide-react**, **recharts**

## Pages

| Route        | Contenu                                                                 |
| ------------ | ----------------------------------------------------------------------- |
| `/login`     | Connexion / inscription (bascule), erreurs API affichées                |
| `/`          | Tableau de bord : 4 cartes, BarChart constats/sévérité, derniers scans  |
| `/cibles`    | Registre des cibles, ajout / suppression, badge de périmètre            |
| `/scans`     | Lancement (cibles autorisées, profil quick/full), historique            |
| `/scans/:id` | Métadonnées du scan + tableau des constats (port, service, sévérité…)   |
| `/rapports`  | État vide : génération PDF prévue en v0.5                               |
| `/doctrine`  | Les cinq piliers de la doctrine nationale de cyber-défense              |

Toute route autre que `/login` exige une session ; sinon redirection vers `/login`.

## Développement

Prérequis : Node ≥ 20, et le backend Sentinelle sur `http://localhost:8000`.

```bash
npm install
npm run dev        # http://localhost:5173 — /api est proxifié vers localhost:8000
```

Scripts :

```bash
npm run dev         # serveur de dev Vite
npm run build       # build de production -> dist/
npm run typecheck   # tsc --noEmit (vérification des types, hors build)
npm run preview     # prévisualisation du build
```

## Docker

Image multi-étapes : build Node 20 Alpine, puis `nginx:alpine` sert `dist/` et
proxifie `/api/` vers `http://api:8000/api/` (service backend nommé `api` sur le
réseau Docker, p. ex. via docker-compose).

```bash
docker build -t sentinelle-frontend .
docker run --rm -p 8080:80 sentinelle-frontend
# -> http://localhost:8080 (nécessite le service `api:8000` joignable)
```

## Structure

```
frontend/
├── Dockerfile              # multi-étapes : node:20-alpine -> nginx:alpine
├── nginx.conf              # SPA fallback + proxy /api/ -> http://api:8000/api/
├── index.html              # lang="fr", titre « Sentinelle — Cyber-défense »
├── vite.config.ts          # proxy dev /api -> http://localhost:8000
├── tailwind.config.js      # Tailwind v3
├── postcss.config.js
└── src/
    ├── main.tsx            # providers (react-query, router, auth)
    ├── App.tsx             # routes + garde
    ├── index.css           # Tailwind + classes utilitaires (.panel, .input, .badge…)
    ├── lib/                # client axios, types API, formatage
    ├── auth/               # AuthContext (login / register / logout, /auth/me)
    ├── components/         # Layout (sidebar + topbar), badges, cartes, états
    └── pages/              # Login, Dashboard, Cibles, Scans, ScanDetail, Rapports, Doctrine
```
