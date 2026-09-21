# Roadmap — Sentinelle

Fil directeur : partir de l'audit offensif **encadré** (ce qui existe) vers la
défense et la veille (ce qui impressionne un État), en gardant une seule
interface.

## ✅ v0.1 — Socle (cette version)

- Auth JWT, cibles + garde-fou de périmètre côté serveur
- Scans nmap async (worker isolé), constats structurés, dashboard temps réel
- Docker Compose, CI GitHub Actions, docs (archi, doctrine, règles d'engagement)

## ✅ v0.2 — Audit vulnérabilités

- [x] Intégration **nuclei** dans le worker (templates communautaires)
- [x] Correspondance service/version → **CVE** (API NVD)
- [x] Score de risque par cible et par scan
- [x] Export CSV des constats

## ✅ v0.3 — Défense (le virage stratégique)

- [x] Ingestion **Suricata / Zeek** (capteur réseau dans le lab) → alertes dans
      le même dashboard
- [x] Règles de détection simples (scan de port, brute force SSH, beaconing)
- [x] Migrations Alembic, rétention configurable

## ✅ v0.4 — Veille menaces (threat intel)

- [x] Connecteurs flux publics (MISP, AlienVault OTX, CERT-FR)
- [x] Corrélation IOC ↔ constats locaux
- [x] Carte des campagnes ciblant le pays (page dédiée)

## v0.5 — Rapports & gouvernance

- [ ] **Rapports PDF** générés (synthèse dirigeant + annexe technique)
- [ ] RBAC fin (admin / analyste / lecteur), journal d'audit complet
- [ ] SSO / OIDC (Keycloak) — prérequis secteur public

## v0.6 — Durcissement production

- [ ] Kubernetes (chart Helm), secrets externalisés (Vault)
- [ ] Chiffrement au repos des constats sensibles
- [ ] Tests de charge, plan de reprise, monitoring (Prometheus/Grafana)

---

### Indicateurs de crédibilité (pour le dossier public)

- Couverture de tests backend > 80 %
- Démo rejouable en < 5 min (`docker compose up` + seed)
- 1 article de blog technique par version (le volet « rayonner »)
