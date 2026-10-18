# 🛡️ SENTINEL-ZERO : Autonomous DevSecOps & Self-Healing Agent

**SENTINEL-ZERO** is an autonomous Site Reliability Engineering (SRE) agent. It intercepts Layer 7 malicious payloads, analyzes them via an LLM, and applies zero-downtime hot-patches to a running WSGI server.

## 🏗️ Architecture (Phase 0 - Python PoC)

```text
[Attacker] ---> (HTTP 80) ---> [Traefik Proxy] ---> [Gunicorn/Flask API]
                                    |                      ^
                               (Log Stream)                | (AST-Validated Patch)
                                    v                      |
                            [SENTINEL AGENT] -----------------
                            1. Regex Pre-filter (L1)
                            2. LLM Payload Analysis (L2)
                            3. Circuit Breaker / Mock (Failover)
                            4. Iptables Netfilter Ban
```

## ⚡ Core Features
- **Asynchronous Log Interception:** Non-blocking I/O monitoring of Traefik access logs.
- **Zero-Downtime Hot-Patching:** Modifies running Python endpoints and triggers Gunicorn worker reloads (`--reload`) without dropping legitimate traffic.
- **Resilience Mechanisms:** Incorporates Exponential Backoff and a local Circuit Breaker to prevent third-party API quota exhaustion under DDoS conditions.
- **Idempotent Netfilter Bans:** Safely injects `DOCKER-USER` iptables rules to drop malicious IPs at the network stack.

## 🚀 Tech Stack
- **Infrastructure:** Docker Compose, Traefik v2, Gunicorn WSGI
- **Security Agent:** Python 3, Threading, AST (Abstract Syntax Tree) Validation
- **AI Engine:** Google Gemini Flash
