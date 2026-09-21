## Ce que fait cette PR

<!-- Deux ou trois phrases. Le « pourquoi » avant le « comment ». -->

Closes #

## Comment c'est vérifié

<!-- Des commandes, pas des affirmations. Cocher ce qui a été exécuté. -->

- [ ] `cd backend && pytest -q` (suite complète)
- [ ] `make coverage` — barrière de 80 %, et > 90 % sur les modules critiques
- [ ] `cd frontend && npm run typecheck && npm run build`
- [ ] migrations : `alembic upgrade head && alembic check` (aucune dérive)
- [ ] Helm : `helm lint --strict helm/sentinelle && helm template sentinelle helm/sentinelle`
- [ ] secrets : `gitleaks detect --source . --config .gitleaks.toml --redact`

## Points d'attention

<!-- Ce qu'un relecteur doit regarder en priorité, ou ce qu'on assume de ne pas
     avoir traité (et pourquoi). « Rien de particulier » est une réponse valable. -->

## Capture / trace

<!-- Pour un changement d'interface : avant/après. Sinon, supprimer cette section. -->
