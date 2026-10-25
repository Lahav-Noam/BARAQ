# BARAQ

AI-Powered Security Operations Platform for Windows endpoints.

> Self-hosted SOC: telemetry collection, hybrid rule + ML detection, MITRE ATT&CK mapping, investigation, SOAR automation, threat intelligence, and AI-assisted analysis.

[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React%2019-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![CI](https://github.com/natahanjr/BARAQ/actions/workflows/python-package.yml/badge.svg)](https://github.com/natahanjr/BARAQ/actions)
[![License](https://img.shields.io/badge/license-RazForge-blue)](LICENSE)

---

## Before you run this in production

Read this section first — it is the difference between a demo and a SOC.

- **The production config is fail-closed.** With `BARAQ_ENV=production` the
  server refuses to start on: public `baraq-dev-*` API keys, unparseable keys,
  `localhost` in CORS origins, threat intel disabled, `ENCRYPT_AT_REST=0`,
  destructive SOAR enabled, public metrics, a missing session secret, or
  `BARAQ_TLS=1` without a readable certificate.
- **Check readiness with one command:**
  `venv\Scripts\python scripts\preflight.py --url https://<host>:8443 --ca-file certs\baraq.crt`
  It runs 17 checks and exits non-zero on any hard failure. Use it to gate a
  change window.
- **Deploy agents with the installer, not by hand:**
  `powershell -ExecutionPolicy Bypass -File scripts\install_agent.ps1 -Server https://<host>:8443 -Key <secret> -Org <dept> -TlsCert certs\baraq.crt`
  The installer verifies the agent actually reports before reporting success,
  and tells you plainly when auto-start is not configured.
- **Back up and prove the restore.** `scripts\install_backup_task.ps1` installs
  the 03:00 task; `scripts\db_backup.py` locates `pg_dump` itself. Restore the
  newest archive into a scratch database before you trust it.
- **Paging must be configured and tested** or nothing wakes anyone. Email and
  Telegram are supported with per-channel severity floors
  (`BARAQ_NOTIFY_MIN_SEVERITY`, `BARAQ_TELEGRAM_MIN_SEVERITY`); see
  `scripts\show_paging_routes.py`.
- **Response actions are simulated** while
  `BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED=0` (the default). Containment
  playbooks ship disabled. A `block_ip` has no TTL — undo it with `unblock_ip`.
- **ML is advisory, not an autonomous blocker.** The loaded v121 bundle has no
  campaign-held-out validation and is shadow/advisory only. Score monitoring is
  exposed at `/api/system/ml/deployment`; the promotion gate and rollout
  procedure are in
  [`docs/ml-deployment-readiness.md`](docs/ml-deployment-readiness.md).
- The cutover procedure, go/no-go gates and rollback triggers are in
  [`docs/CUTOVER_RUNBOOK.md`](docs/CUTOVER_RUNBOOK.md). The full record of the
  2026-09 hardening pass, including known issues, is in
  [`CHANGELOG.md`](CHANGELOG.md).
- **BARAQ is a single-tenant platform** — one organization, no external
  customers. Most read paths are org-scoped per analyst, but fifteen API
  surfaces (the v2 alerts and incidents APIs, risk, UEBA, investigation, intel,
  compliance, telemetry, evaluation) have no tenant column and are reachable by
  any authenticated account. Read
  [`docs/SINGLE_TENANT.md`](docs/SINGLE_TENANT.md) before onboarding a second
  organization.

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ
docker compose up -d
```

That's it. Backend on `http://localhost:8001`, PostgreSQL and Redis included.

**Production compose requires secrets.** `compose.yml` refuses to render
without `POSTGRES_PASSWORD`, `BARAQ_API_KEYS`, `BARAQ_TOKEN_SECRET`,
`BARAQ_ADMIN_PASSWORD`, `REDIS_PASSWORD` and `GRAFANA_ADMIN_PASSWORD` — this is
deliberate, not a bug. Copy `.env.example` and fill them in, or export them
from your secret store.

```bash
cp .env.example .env    # then edit: no baraq-dev-* keys in production
docker compose up -d
```

**One-liner install (Linux/macOS):**
```bash
curl -fsSL https://raw.githubusercontent.com/natahanjr/BARAQ/main/install.sh | bash
```

### Option 2: Windows (Native)

**Requirements:** Windows 10/11, Python 3.12+, Node.js 22+, PostgreSQL 16+

```powershell
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ
.\start.bat
```

### URLs

| What | URL |
|---|---|
| Dashboard | `http://localhost:8001` |
| API docs (Swagger) | `http://localhost:8001/docs` |
| API docs (ReDoc) | `http://localhost:8001/redoc` |
| Health check | `http://localhost:8001/api/health` |

### Default Credentials

| User | Password | Role |
|---|---|---|
| `admin` | `BaraqAdmin2026!` | Admin |

---

## Docker Compose Services

| Service | Port | Description |
|---|---|---|
| `api` | 8001 | FastAPI backend (API + scheduler) |
| `db` | 5432 | PostgreSQL 16 |
| `redis` | 6379 | Redis 7 (caching, rate limiting) |
| `prometheus` | 9090 | Metrics (opt-in: `--profile monitoring`) |
| `grafana` | 3000 | Dashboards (opt-in: `--profile monitoring`) |

```bash
# Development (API + DB + Redis)
docker compose up -d

# With monitoring (Prometheus + Grafana)
docker compose --profile monitoring up -d

# Production
docker compose --profile production up -d
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12+, FastAPI, SQLAlchemy, psycopg3 |
| Frontend | React 19, Tailwind CSS 4, Recharts, Vite 8 |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Detection | 100 native rules + 2,512 Sigma rules + 11 correlation chains |
| ML | Isolation Forest + XGBoost + Cross-Stream Markov + Ensemble Meta-Learner |
| Intelligence | IOC enrichment from 9 providers (AbuseIPDB, OTX, VirusTotal, abuse.ch, etc.) |
| Security | RBAC, TOTP 2FA, LDAP/OIDC SSO, AES-256-GCM at rest, SHA-256 audit chain |

---

## Project Structure

```
BARAQ/
├── backend/
│   ├── api/           # FastAPI routers
│   ├── collectors/    # Windows event log, process, network, PowerShell, Sysmon
│   ├── database/      # SQLAlchemy models + PostgreSQL
│   ├── detection/     # 100 rules, Sigma engine, 11 correlation chains
│   ├── ml/            # 4-layer ML: IF + XGB + Markov + Ensemble
│   ├── response/      # SOAR actions (Windows-native)
│   ├── threatintel/   # IOC enrichment (9 providers)
│   └── vulnscan/      # CVE matching engine
├── frontend/          # React 19 dashboard
├── scripts/           # Agent, build, seed_demo, sigma_pull, tune
├── tests/             # 1,300+ tests
├── deploy/            # Docker, Prometheus, Grafana configs
└── docs/              # Full documentation suite
```

---

## Development

```bash
# Clone and setup
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ

# Docker (recommended)
docker compose up -d

# Or native (Windows)
.\start.bat

# Run tests
python -m pytest tests -v

# Lint
ruff check .

# Type check
pyright backend
```

---

## API Documentation

BARAQ auto-generates OpenAPI documentation:

| Format | URL |
|---|---|
| Swagger UI | `http://localhost:8001/docs` |
| ReDoc | `http://localhost:8001/redoc` |
| OpenAPI JSON | `http://localhost:8001/openapi.json` |

---

## Documentation

| Document | Description |
|---|---|
| [`docs/PRODUCTION_DEPLOY.md`](docs/PRODUCTION_DEPLOY.md) | **Production LAN runbook (Windows, 50–200 endpoints, replace Splunk)** |
| [`docs/BARAQ_Combined_Guide.md`](docs/BARAQ_Combined_Guide.md) | Operator/maintenance walkthrough |
| [`docs/user-guide.md`](docs/user-guide.md) | Complete operator guide |
| [`docs/architecture.md`](docs/architecture.md) | System architecture and data flow |
| [`docs/ml_strategy_and_validation.md`](docs/ml_strategy_and_validation.md) | ML training and validation |
| [`docs/ml-deployment-readiness.md`](docs/ml-deployment-readiness.md) | ML shadow-mode contract, promotion gate, monitoring, rollback |
| [`docs/botsv1-ml-benchmark.md`](docs/botsv1-ml-benchmark.md) | BOTSv1 benchmark and retracted S1/context results |
| [`docs/deployment.md`](docs/deployment.md) | Fleet deployment guide |
| [`docs/dataset-import.md`](docs/dataset-import.md) | External dataset import guide |
| [`docs/ml-training.md`](docs/ml-training.md) | ML training configuration |

---

## Dataset Statistics

BARAQ supports importing external security datasets for ML training:

| Dataset | Events | Format | Source |
|---|---|---|---|
| OTRF Security-Datasets | 310K+ | JSON/CSV | [OTRF](https://github.com/OTRF/Security-Datasets) |
| BOTSv1 | 1.8M | CSV | [Splunk](https://github.com/splunk/botsv1) |
| BOTES | 2M+ | CSV | [Splunk](https://github.com/splunk/botes) |

---

## ML Performance

Measured on the **full in-distribution evaluation set** (310K synthetic OTRF
records). These are *not* hold-out numbers and should not be read as expected
performance on a real network.

| Model | AUC | Recall | Samples |
|---|---|---|---|
| Network (v12) | 0.999 | 99.7% | 310K |
| Process (v10) | 0.865 | 86.5% | 310K |
| Login (v37) | 0.870 | 21.4% | 995 |
| **Full-DB Eval** | **0.999** | **100%** | **310K** |

> **These figures overstate real-world detection.** They are measured on
> synthetic data drawn from the same distribution the model was trained on. The
> honest generalisation numbers come from the hold-out split, which uses attack
> scenarios the detector has never seen: the **rule and hybrid layers reach
> 0.939 recall**, while the **ML layer alone reaches 0.286**. Treat the table
> above as "the model fits its training distribution", not "the model detects
> 99.7% of attacks". Current status is tracked in
> [`ROADMAP.md`](ROADMAP.md) item 3.

---

## License

Copyright (c) 2026 [Natahan](https://github.com/natahanjr) — [RazForge Lab](https://github.com/natahanjr)

Licensed under the [RazForge License](https://github.com/RazForge/.github/blob/main/RAZFORGE-SOURCE-AVAILABLE-LICENSE.md).

---

<div align="center">

[![Part of RazForge](https://img.shields.io/badge/Part%20of-RazForge-1a1a2e?style=for-the-badge&logo=github&logoColor=white&labelColor=16213e)](https://github.com/RazForge)

</div>
