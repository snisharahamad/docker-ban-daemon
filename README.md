# Sentinel-Zero (Enterprise Edition)
Agent SRE/DevSecOps autonome en Golang.

## Architecture V4.0
- **Multi-Tenancy :** Configuration dynamique par client via JSON.
- **Cache Sémantique (SHA-256) :** Déduplication des requêtes IA pour une latence de 0ms sur les attaques connues.
- **Télémétrie :** Endpoint HTTP `/metrics` exposant les statistiques de blocage en temps réel.
- **Remédiation L3 :** Frappe Kernel dynamique (Iptables `DOCKER-USER`) avec Auto-Unban (TTL).
