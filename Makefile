.PHONY: up down logs seed seed-demo test coverage e2e screenshots migrate migration sensor sso monitoring secrets-init secrets-edit secrets-export rotate-key rules dev-api dev-web dev-worker

up:            ## Build et lance toute la stack
	docker compose up -d --build

down:          ## Stoppe la stack
	docker compose down

logs:          ## Suit les logs
	docker compose logs -f

seed:          ## Crée le compte démo + cible lab
	docker compose exec api python seed.py

test:          ## Tests backend
	cd backend && pytest -q

seed-demo:     ## Remplit la base locale de données de démonstration
	cd backend && python seed_demo.py

e2e:           ## Smoke E2E Playwright (nécessite la pile démarrée)
	cd frontend && npm run e2e

screenshots:   ## Régénère les captures et le GIF du README
	./scripts/capture-screenshots.sh

coverage:      ## Couverture de tests avec barrière (identique à la CI)
	cd backend && pytest -q --cov=app --cov-report=term-missing:skip-covered --cov-config=.coveragerc

migrate:       ## Applique les migrations Alembic (base locale)
	cd backend && alembic upgrade head

migration:     ## Nouvelle révision : make migration m="ajout de la table x"
	cd backend && alembic revision --autogenerate -m "$(m)"

sensor:        ## Démarre le capteur Suricata du lab (profil `lab`)
	docker compose --profile lab up -d sensor

sso:           ## Démarre Keycloak (profil `sso`) — nécessite SENTINELLE_CLIENT_SECRET
	docker compose --profile sso up -d keycloak

monitoring:    ## Démarre Prometheus + Grafana (profil `monitoring`)
	docker compose --profile monitoring up -d prometheus grafana

secrets-init:  ## Crée le fichier de secrets chiffre (SOPS + age)
	./scripts/secrets.sh init

secrets-edit:  ## Modifie les secrets chiffrés
	./scripts/secrets.sh edit

secrets-export:## Émet les export VAR=… pour la session courante (à évaluer)
	./scripts/secrets.sh export

rotate-key:    ## Re-chiffre les champs sensibles vers une nouvelle clé (DRY=1 pour simuler)
	@test -n "$$FIELD_ENCRYPTION_KEY_OLD" -a -n "$$FIELD_ENCRYPTION_KEY_NEW" || \
		{ echo "Définir FIELD_ENCRYPTION_KEY_OLD et FIELD_ENCRYPTION_KEY_NEW" >&2; exit 2; }
	cd backend && python scripts/rotate_field_key.py $(if $(DRY),--dry-run,)

rules:         ## Vérifie que le fichier de règles de détection est valide
	cd backend && python -c "from app.services.detection import load_rules; \
	rules = load_rules(); print(f'{len(rules)} règle(s) chargée(s) :'); \
	[print(' -', r.name, f'({r.kind}, seuil {r.threshold}/{r.window_seconds}s)') for r in rules]"

dev-api:       ## API en local (SQLite)
	cd backend && uvicorn app.main:app --reload

dev-worker:    ## Worker de scan en local (nécessite nmap + redis)
	cd backend && arq app.worker.settings.WorkerSettings

dev-web:       ## Front en local
	cd frontend && npm run dev
