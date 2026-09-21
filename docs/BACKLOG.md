# Backlog — Sentinelle

Le backlog complet est **versionné dans le dépôt** (`backlog-issues.json`) et
synchronisable sur GitHub en une commande. Rien ne vit « dans la tête ».

## Synchroniser avec GitHub

```bash
# Aperçu sans rien créer
python3 scripts/create_github_issues.py --repo kitokoh/sentinelle --dry-run

# Création (idempotent : relançable sans doublons)
GITHUB_TOKEN=<token-scope-repo> python3 scripts/create_github_issues.py --repo kitokoh/sentinelle
```

Le script crée les **labels** (type / priorité / scope), les **milestones**
(v0.3 → v0.6 + Qualité continue) et les **issues** (titre, corps, critères
d'acceptation). Les éléments existants sont ignorés.

## État d'avancement

| Milestone | Contenu | État |
|---|---|---|
| v0.1 — Socle | Auth JWT, cibles + garde-fou, scans nmap async, dashboard | ✅ livré |
| v0.2 — Audit vulnérabilités | nuclei, CVE (NVD), score de risque, export CSV | ✅ livré |
| v0.3 — Défense | Suricata, règles de détection, alertes, Alembic | ✅ livré |
| v0.4 — Threat Intel | MISP/OTX/CERT, corrélation IoC, carte | ✅ livré |
| v0.5 — Rapports & gouvernance | PDF, RBAC, journal d'audit, SSO, multi-tenant | ✅ livré |
| v0.6 — Production | Helm, secrets, chiffrement, monitoring, PRA | ✅ livré |
| Qualité continue | Couverture 80 %, E2E, gouvernance dépôt, comm | ✅ livré |

## Règles de triage

- **priority:high** = sans ça, le projet n'est pas crédible devant un État
  (Alembic, RBAC, journal d'audit, rapports PDF, couverture, screenshots).
- Une issue n'est « done » que si : code + tests + doc, CI verte.
- Ordre recommandé à l'intérieur d'un milestone : backend → worker → front → ops.
- Toute nouvelle idée = nouvelle entrée dans `backlog-issues.json` + relance du
  script. Le JSON reste la source de vérité.

## Definition of Done (rappel)

1. Tests écrits et verts (backend : pytest ; front : typecheck + build).
2. Pas de secret, pas de régression sur le garde-fou de périmètre.
3. Doc à jour (README ou docs/).
4. CI verte sur la PR.
