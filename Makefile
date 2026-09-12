.PHONY: up down logs seed test dev-api dev-web dev-worker

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

dev-api:       ## API en local (SQLite)
	cd backend && uvicorn app.main:app --reload

dev-worker:    ## Worker de scan en local (nécessite nmap + redis)
	cd backend && arq app.worker.settings.WorkerSettings

dev-web:       ## Front en local
	cd frontend && npm run dev
