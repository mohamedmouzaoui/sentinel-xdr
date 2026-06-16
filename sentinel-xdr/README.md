# 🛡️ Sentinel XDR Pro — v3.0

## 🚀 Démarrage (Ubuntu VM 4.7 Go RAM)

```bash
# 1. Installe Docker si pas encore fait
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# 2. Dézippe et entre dans le dossier
unzip sentinel-xdr-pro.zip
cd sentinel-xdr-pro

# 3. Lance tout
cp .env.example .env
docker compose up -d --build
```

⚠️ **TheHive + Cassandra prennent 3-5 minutes à démarrer** — c'est normal.

---

## 🌐 Accès aux services

| Service | URL | Login |
|---------|-----|-------|
| **Frontend SOC** | http://localhost:3000 | admin / SentinelXDR@2024! |
| **API Docs** | http://localhost:8000/api/docs | — |
| **TheHive** | http://localhost:9000 | admin@thehive.local / secret1234 |
| **Grafana** | http://localhost:3001 | admin / SentinelAdmin2024 |
| **Prometheus** | http://localhost:9090 | — |

---

## 🐳 Commandes utiles

```bash
docker compose ps              # état de tous les conteneurs
docker compose logs -f         # logs en direct
docker compose logs -f backend # logs backend seulement
docker compose down            # arrêter tout
docker compose up -d           # redémarrer
```

## 🔍 Vérifier que tout marche

```bash
curl http://localhost:8000/health   # doit retourner {"status":"ok"}
curl http://localhost:9000/api/status  # TheHive status
```

---

## ✅ Fonctionnalités

- JWT Auth + RBAC 6 rôles
- Multi-tenant
- ISO 27001 Audit Log
- Incidents workflow 7 statuts + timeline + SLA
- WebSocket temps réel
- CTI/IoC STIX 2.1 / MISP
- SOAR Playbooks (terminal animé) → TheHive auto
- AbuseIPDB + VirusTotal (si clés dans .env)
- PDF Reports
- MITRE ATT&CK Kill Chain dashboard
- ML IsolationForest + RandomForest
- Sigma rules
