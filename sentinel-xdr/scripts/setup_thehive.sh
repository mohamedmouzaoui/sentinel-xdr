#!/bin/bash
# ════════════════════════════════════════════════════════════════
# scripts/setup_thehive.sh
# Crée un utilisateur admin TheHive et récupère l'API key
# À lancer APRÈS docker compose up -d et que TheHive est healthy
# ════════════════════════════════════════════════════════════════

THEHIVE_URL="http://localhost:9000"
THEHIVE_ADMIN_USER="admin@thehive.local"
THEHIVE_ADMIN_PASS="secret1234"

echo "⏳ Attente que TheHive soit prêt..."
until curl -sf "$THEHIVE_URL/api/status" > /dev/null; do
  sleep 5
  echo "  ... encore en démarrage"
done

echo "✅ TheHive est prêt"

# Créer un utilisateur API
API_KEY=$(curl -s -u "$THEHIVE_ADMIN_USER:$THEHIVE_ADMIN_PASS" \
  -X POST "$THEHIVE_URL/api/v1/user" \
  -H "Content-Type: application/json" \
  -d '{
    "login": "sentinel-xdr@thehive.local",
    "name": "Sentinel XDR",
    "profile": "analyst",
    "email": "sentinel-xdr@thehive.local"
  }' | python3 -c "import sys,json; print(json.load(sys.stdin).get('_id',''))" 2>/dev/null)

if [ -n "$API_KEY" ]; then
  echo "✅ Utilisateur créé — ID: $API_KEY"
  echo ""
  echo "Ajoute cette ligne dans ton .env :"
  echo "  THEHIVE_API_KEY=$API_KEY"
  echo ""
  echo "Puis redémarre le backend :"
  echo "  docker compose restart backend"
else
  echo "ℹ️  TheHive fonctionne — récupère l'API key manuellement sur http://localhost:9000"
  echo "   Utilisateur par défaut : admin@thehive.local / secret1234"
fi
