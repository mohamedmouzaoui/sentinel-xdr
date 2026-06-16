# ════════════════════════════════════════════════════════════════
# Sentinel XDR Pro — Makefile
# Usage: make start
# ════════════════════════════════════════════════════════════════

.PHONY: start stop restart logs status clean setup-thehive

start:
	@echo "🚀 Démarrage de Sentinel XDR Pro..."
	@cp -n .env.example .env 2>/dev/null || true
	@mkdir -p logs
	docker compose up -d --build
	@echo ""
	@echo "✅ Démarré ! Accès :"
	@echo "   Frontend  → http://localhost:3000  (admin / SentinelXDR@2024!)"
	@echo "   API Docs  → http://localhost:8000/api/docs"
	@echo "   TheHive   → http://localhost:9000  (attend ~2min)"
	@echo "   Grafana   → http://localhost:3001  (admin / SentinelAdmin2024)"
	@echo ""
	@echo "⏳ TheHive prend ~2-3 min à démarrer (Cassandra doit initialiser)"

stop:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f --tail=100

logs-backend:
	docker compose logs -f backend

status:
	docker compose ps

clean:
	docker compose down -v
	@echo "⚠️  Tous les volumes supprimés"

setup-thehive:
	@bash scripts/setup_thehive.sh

# Tester que tout marche
test:
	@echo "Test API health..."
	@curl -sf http://localhost:8000/health && echo "✅ Backend OK" || echo "❌ Backend KO"
	@curl -sf http://localhost:3000 && echo "✅ Frontend OK" || echo "❌ Frontend KO"
	@curl -sf http://localhost:9000/api/status && echo "✅ TheHive OK" || echo "⏳ TheHive pas encore prêt"
