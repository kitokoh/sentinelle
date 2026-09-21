.PHONY: up down logs seed test migrate migration sensor sso rules dev-api dev-web dev-worker

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

migrate:       ## Applique les migrations Alembic (base locale)
	cd backend && alembic upgrade head

migration:     ## Nouvelle révision : make migration m="ajout de la table x"
	cd backend && alembic revision --autogenerate -m "$(m)"

sensor:        ## Démarre le capteur Suricata du lab (profil `lab`)
	docker compose --profile lab up -d sensor

sso:           ## Démarre Keycloak (profil `sso`) — nécessite SENTINELLE_CLIENT_SECRET
	docker compose --profile sso up -d keycloak

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
