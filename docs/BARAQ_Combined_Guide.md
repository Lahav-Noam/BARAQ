# BARAQ — Combined Platform Guide

**BARAQ: An Intelligent Lightweight Security Operations Center Framework for Real-Time Windows Endpoint Threat Detection and Incident Analysis**

Version 3.0 · FastAPI backend + React dashboard · local-first, opt-in network exposure.

This single master guide covers the whole product: **system overview**, **architecture**, **deployment & operations**, and a **step-by-step user / analyst guide**. It replaces the need to consult several documents and is accurate against the current codebase.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Features at a Glance](#2-features-at-a-glance)
3. [Architecture](#3-architecture)
4. [Installation & First Run](#4-installation--first-run)
5. [Configuration Reference](#5-configuration-reference)
6. [Security Model](#6-security-model)
7. [Operations Guide (Admin)](#7-operations-guide-admin)
8. [User / Analyst Guide](#8-user--analyst-guide)
9. [Multi-Endpoint Agent Ingest](#9-multi-endpoint-agent-ingest)
10. [Alerting & Notifications](#10-alerting--notifications)
11. [Streaming / SIEM Forwarding](#11-streaming--siem-forwarding)
12. [REST API Overview](#12-rest-api-overview)
13. [Testing & Quality](#13-testing--quality)
14. [Troubleshooting](#14-troubleshooting)
15. [Glossary](#15-glossary)

---

## 1. Overview

BARAQ is a lightweight, production-oriented SOC platform that runs entirely on a single Windows machine — **no cloud, no heavy infrastructure**. It collects real Windows telemetry, normalises events, detects attacks through a **hybrid rule-based + machine-learning engine**, maps findings to **MITRE ATT&CK**, computes **hybrid risk scores**, and presents everything in a professional real-time dashboard.

It also generates executive/technical reports, exposes a full REST API, supports SSO/MFA user management, pushes real-time updates over WebSockets, and includes an evaluation framework that measures detection accuracy on real host telemetry.

Designed target: **Windows 11 laptop, Intel i5, 12 GB RAM, any SSD.**

---

## 2. Features at a Glance

| Layer | Capabilities |
|---|---|
| **Collection** | Windows Security event log (4624, 4625, 4720, 4726, 4732, 4740, 4672…), running/new processes with parent/child trees, active TCP connections + listening ports, PowerShell operational log, **Sysmon** (E1, E3, E10, E11, E13, E23) |
| **Processing** | Event normalisation (Event ID / Category / User / Risk / Timestamp / Host) with numeric 0–100 risk scoring |
| **Rule Detection** | 23+ rules: Bruteforce (T1110), Suspicious PowerShell (T1059.001), Privilege Escalation, Persistence, Network Recon, Lateral Movement, Data Staging, Malware File, Email/URL Scan, DNS/HTTP Exfiltration, USB Device, Kill-Chain Correlation, LSASS Memory Access, Registry Run Keys, Scheduled Task, WMI Event Subscription, Security Log Tampering, Binary Masquerading, Hiding, Signature (LOLBIN) and more |
| **Alert Aggregation** | Rule-level deduplication (one open alert per signature) with repeat-trigger severity escalation (`trigger_count`, LOW→MEDIUM→HIGH→CRITICAL) and per-rule throttling |
| **ML Detection** | Per-behavior anomaly analysis (logon/process/network) with Isolation Forest + supervised RandomForest/XGBoost classifier, persisted model metadata, staleness signal + scheduler auto-retraining, drift guard |
| **Hybrid Risk Scoring** | Alert risk = 60% rule score + 40% ML anomaly · 0–100 score · LOW/MEDIUM/HIGH/CRITICAL level |
| **MITRE ATT&CK** | Every alert enriched with technique ID, name, tactic, confidence and recommendation |
| **Dashboard** | Security score, risk level, system status, timeline, threat categories, severity distribution, attack stats, user behavior, detection methods, recent alerts, top attack sources |
| **Investigation** | Kill-chain reconstruction, related events (±30 min), network context, AI explanations, SOAR actions |
| **AI Assistant** | Local rule/TF-IDF engine: explains alerts, summarizes, recommends remediation, keeps history, answers from MITRE + knowledge base |
| **Real-Time Alerting** | Optional webhook + SMTP notifications, Windows toast, escalate high/critical |
| **Reporting** | Executive & technical reports exported as PDF / HTML / JSON / CSV |
| **Evaluation** | Runs attack scenarios vs baseline in an isolated DB; reports accuracy/precision/recall/F1/FPR/detection-time |
| **API** | Full FastAPI REST API with OpenAPI docs at `/docs`, RBAC (analyst/admin) |

---

## 3. Architecture

```
┌─────────────────────────────── Windows Host ───────────────────────────────┐
│                                                                            │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  CollectorManager (backend/collectors/)                             │  │
│   │   • EventLog (Security/System/PowerShell/Sysmon channels)           │  │
│   │   • Process/Network snapshot                                        │  │
│   │   • USB, Sysmon enrichment, mail/domain watchlists                  │  │
│   └──────┬──────────────────────────────────────────────────────────────┘  │
│          │ raw records (every 15 s by default)                           │
│          ▼                                                                │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  Pipeline – backend/api/system.py run_pipeline()                   │  │
│   │   1. normalise            → NormalizedEvent (risk 0–100)            │  │
│   │   2. rules_engine        → candidate detections                     │  │
│   │   3. aggregator/alerting → dedupe, escalate, throttle, risk score    │  │
│   │   4. persist + publish   → DB (SQLite/Postgres) + realtime hub       │  │
│   └──────┬──────────────────────────────────────────────────────────────┘  │
│          ▼                                                                │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  ML Detector (backend/ml/anomaly.py)                               │  │
│   │   • trained IsolationForests per behavior stream                    │  │
│   │   • supervised classifiers (RF/XGBoost) on labeled verdicts        │  │
│   │   • staleness/drift detection → background auto-retraining          │  │
│   └──────┬──────────────────────────────────────────────────────────────┘  │
│          ▼                                                                │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │  FastAPI server (backend/main.py, uvicorn on :8001 / :8443)        │  │
│   │   routers: dashboard, alerts, events, investigation, reports,      │  │
│   │            assistant, evaluation, system, endpoints, incidents,    │  │
│   │            intel, auth, realtime(WS)                               │  │
│   │   middleware: API-key RBAC, CSRF double-submit, body-size limit    │  │
│   │   static: serves built SPA (frontend/dist) with cache policy       │  │
│   └──────┬──────────────────────────────────────────────────────────────┘  │
│          │ HTTP/WS                                                       │
│   ┌──────▼──────────────────────────────────────────────────────────────┐  │
│   │  Dashboard – React SPA (frontend/src)                              │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Runtime components

| Component | Location | Role |
|---|---|---|
| Scheduler thread | `backend/main.py::_scheduler_loop` | Run collection + detection every 15 s, publish status, snapshot, ML analysis, retention purge (~1 h) |
| Broadcast Hub | `backend/realtime.py` | Fan-out of `status`, `alert`, `incident` events to connected WebSocket clients |
| Secret vault | `backend/vault.py` (+ `secrets.dat`) | DPAPI-protected storage for admin password, API keys, token secret, encryption key, external provider keys |
| Crypto | `backend/crypto.py` | AES-256-GCM field-level encryption at rest (messages, evidence, command lines, audit detail) |
| Auth | `backend/auth.py`, `backend/api/auth.py` | Session tokens (JWT-ish signed), PBKDF2 password hashing, TOTP MFA, RBAC roles |
| SSO | `backend/oidc.py`, `backend/ldap.py` | Optional OIDC (Google/Entra/Okta-compatible) and LDAP/AD directory login |
| Streaming | `backend/streaming.py` | Optional outbound Kafka / Redis Streams / Elasticsearch forwarding of normalised events |

### 3.2 Data model (SQLAlchemy)

Primary entities in `backend/database/models.py`:

- **User** — operator account (PBKDF2 hash, role, TOTP MFA)
- **NormalizedEvent** — normalised telemetry (canonical timestamp, risk, channel, source)
- **Alert** — a correlated detection (rule, severity, risk_score, hybrid risk, MITRE fields, evidence, notes, payload snapshot)
- **Incident** — mapping alert groups; captures event links, comments, status, resolution
- **EventLogSnapshot / ProcessSnapshot / NetConnSnapshot / SysEventLog** — snapshots by channel
- **AuditLog** — every RBAC + state change (auth events, user management, report generation)
- **Assistant chat / Intent** — assistant conversations and resolution intents
- **Report** — generated reports metadata + file path
- **DetectionVerdict** — analyst feedback on alerts (used to retrain ML)
- **ReputationCache** — threat-intel lookups by indicator

The default database is local SQLite (`database/baraq.db`). Setting `BARAQ_DATABASE_URL` to a `postgres://...` URL switches to PostgreSQL (see section 7.3 *Reroute to PostgreSQL*).

### 3.3 SPA delivery

The built SPA (`frontend/dist`) is served by FastAPI as a single origin (no separate web server required). Cache headers are intentionally split:

- **index.html and any SPA fallback** → `Cache-Control: no-store` (always pick up the newest asset hashes)
- **/assets/*** (Vite hash-tagged) → `public, max-age=31536000, immutable`

This split is what prevents the classic "blank/black screen after a deploy" caused by a stale cached HTML referencing old hashed bundles.

---

## 4. Installation & First Run

### 4.1 System requirements

- Windows 10/11 (target Windows 11)
- Python 3.11+
- Node.js 18+ (only needed to build the dashboard the first time)
- Optional: PostgreSQL for fleet-scale deployments

### 4.2 One-click launch

```
start.bat            # local only:  http://127.0.0.1:8001
start.bat lan        # LAN:         http://<PC-IP>:8001  (opens firewall rule, needs admin)
start.bat secure     # HTTPS:       https://127.0.0.1:8443 (self-signed cert, gen_cert.ps1)
start.bat secure lan # HTTPS + LAN
```

On first run it creates `venv`, installs requirements, and — if `frontend/dist/index.html` is missing — runs `npm install && npm run build` in `frontend/`. It then starts uvicorn and opens the browser after ~4 s.

> **HTTPS note:** the browser will warn about the self-signed cert. Accept once, or run `scripts\import_cert.ps1` on the client to install `certs/baraq.crt` as a trusted root CA (no admin needed; `-Machine` for all users). Production deployments should use a real certificate (see configuration).

### 4.3 First-run credentials

On the very first start, BARAQ generates random credentials, prints a masked
summary exactly once, and writes the full values to
`first_run_credentials.txt` next to the executable (mode 0600; ACL-restricted
to the current user on Windows):

```
BARAQ first-run setup complete
  Dashboard login : admin / <masked-password>
  Full credentials: first_run_credentials.txt
  Admin API key   : baraq-admin-<random>
  Analyst API key : baraq-analyst-<random>
```

The password and API keys are also stored DPAPI-encrypted in `secrets.dat`
(never plaintext on disk). The console forces a password change on first
login and deletes `first_run_credentials.txt` once it succeeds. If you lost
the credentials, an admin can reset via the `users` page → Edit → Reset
password, and API keys are managed in the security / vault documentation.

### 4.4 Verify installation

1. Open `http://127.0.0.1:8001` (or the appropriate URL).
2. Sign in with the admin account.
3. The dashboard loads showing an initial security score and “System Online”.
4. Check `http://127.0.0.1:8001/api/health` returns `{"status":"ok"}`.

---

## 5. Configuration Reference

All tunables live in **`backend/config.py`**, overridable via environment variables or a `.env` file at the project root. Adjust tuning knobs there; do not patch business logic.

### 5.1 Commonly used environment variables

| Variable | Default | Purpose |
|---|---|---|
| `BARAQ_INTERVAL` | `15` | Collection/detection cycle seconds |
| `BARAQ_DATABASE_URL` | `sqlite:///database/baraq.db` | SQLite or Postgres DSN |
| `BARAQ_TLS` | `0` | Set `1` to enable HTTPS + Secure cookies |
| `BARAQ_TLS_CERT` / `BARAQ_TLS_KEY` | `certs/baraq.crt` / `.key` | PEM cert/key paths (gen_cert.ps1) |
| `BARAQ_COOKIE_SECURE` | `0` | Force Secure cookies (auto-on with TLS) |
| `BARAQ_AUTH_ENABLED` | `1` | Disable API-key auth (dev only) |
| `BARAQ_ALLOW_DEV_KEYS` | `1` | Allow the public `baraq-dev-*` keys (set `0` in production) |
| `BARAQ_API_KEYS` | `{}` | JSON map `{"key":"role"}` replacing the dev defaults |
| `BARAQ_ADMIN_PASSWORD` | random | Admin bootstrap; stored in vault |
| `BARAQ_ADMIN_USERNAME` | `admin` | Admin login |
| `BARAQ_TOKEN_SECRET` | random | Secret used to sign session tokens |
| `BARAQ_AGENT_KEYS` | `{...}` | Agent ingest keys (`{"key":"agent-id"}`) |
| `BARAQ_ENCRYPT_AT_REST` | `0` (dev) / ON (packaged exe) | Enable AES-256-GCM field encryption |
| `BARAQ_CSRF_ENABLED` | `1` | Double-submit CSRF token for cookie sessions |
| `BARAQ_MAX_REQUEST_BYTES` | `16 MB` | Reject bodies larger than this (413) |
| `BARAQ_LOG_FORMAT` | `text` | `text` or `json` (SIEM-friendly) |
| `BARAQ_SYSLOG_HOST` / `BARAQ_SYSLOG_PORT` | `""` / `514` | Optional remote syslog collector |
| `BARAQ_SMTP_*` | — | SMTP host/port/user/password/`TO` for alert emails |
| `BARAQ_WEBHOOK_URL` | `""` | Webhook JSON POST for notifications |
| `BARAQ_NOTIFY_MIN_SEVERITY` | `high` | Minimum severity for email/webhook/toast notifications |
| `BARAQ_TELEGRAM_MIN_SEVERITY` | (unset) | Telegram-only floor - set `critical` so a phone only rings for criticals |
| `BARAQ_WEBHOOK_MIN_SEVERITY` | (unset) | Webhook-only floor |
| `BARAQ_THREAT_INTEL*` | see below | Threshold Intel providers (`_ABUSEIPDB_KEY`, `_OTX_KEY`, `_VT_KEY`) |
| `BARAQ_AI_API_URL` / `_KEY` / `_MODEL` | local | Point assistant at the BARAQ AI endpoint |
| `BARAQ_LDAP_ENABLED` / URL / base | off | AD/LDAP SSO config |
| `BARAQ_OIDC_ENABLED` / ISSUER / CLIENT… | off | OpenID SSO config |
| `BARAQ_ELASTICSEARCH_URL` / `INDEX` | empty | Elasticsearch forwarding |

**Deprecated/developer:** the login page no longer hints at a default password. Read the generated credential from `first_run_credentials.txt` (or `secrets.dat`); installs still using the retired `baraqadmin` hash are rotated automatically on startup.

### 5.2 Thresholds tunable in config.py

- Detection window (`DETECTION_WINDOW_MINUTES` = 10), bruteforce threshold (5 failed logons), port-scan threshold (20 distinct ports / 120 s)
- Alert escalation (`ALERT_ESCALATE_AFTER` = 5 retriggers), severity ladder (`low→medium→high→critical`), alert throttling (max 5 new/rule/5 min)
- ML training (`ML_TRAIN_MIN_SAMPLES` = 30, contamination 0.05), target FPR (`ML_TARGET_FPR`=3%), drift guard (`ML_DRIFT_RATE`=0.75)
- Hybrid weights: rule 0.6 / ML 0.4; risk levels MEDIUM 40 / HIGH 65 / CRITICAL 85
- Security score start 100, penalties per severity (critical 14, high 8, medium 4, low 1)

---

## 6. Security Model

### 6.1 Authentication & authorization

- **Session tokens** — signed, expires; never in JS (kept ONLY in an `httpOnly` cookie). All requests also require a valid `X-API-Key`/Bearer bearer token unless opting out in dev.
- **Roles** — `analyst` (read + standard operations) and `admin` (user/RBAC, system config, reports). Enforced by deps in `backend/security.py` (`require_auth`, `require_admin`).
- **MFA (TOTP)** — optional 2FA per user; login may be challenged for a 6-digit code.
- **SSO**: optional OIDC (e.g. Entra / Okta) or LDAP/AD directory login; role groups configurable (e.g. `Domain Admins`→admin).

### 6.2 Data protection

- **At rest** — AES-256-GCM per-field encryption of sensitive free text (event `message`, evidence/notes, alert payload, audit detail, chat). Key in DPAPI vault.
- **Secrets** — admin password, API keys, token secret and external provider keys live DPAPI-encrypted in `secrets.dat`; `.env` is scrubbed of any plaintext secrets automatically.
- **CSRF** — double-submit token (`baraq_csrf` cookie + `X-CSRF-Token` header), enforced on cookie-authenticated state changes.
- **TLS (optional)** — `start.bat secure` or `BARAQ_TLS=1`; forces `Secure` cookies, served on `:8443`.

### 6.3 Transport notes

- Always prefer HTTPS when exposing on LAN (`start.bat secure launch`).
- The default `baraq-dev-admin`/`baraq-dev-analyst` API keys are dev-only: disable with `BARAQ_ALLOW_DEV_KEYS=0` (requires custom keys in vault/.env) in production.

---

## 7. Operations Guide (Admin)

### 7.1 Start / stop

- **Start**: run `start.bat` (or the LAN/HTTPS variants).
- **Stop**: close the console window (Ctrl+C). The scheduler thread stops with the server.
- **No scheduler**: `set BARAQ_NO_SCHEDULER=1` to disable background collection/detection entirely (e.g., running the API only).
- **Test / dev isolation**: `set BARAQ_TEST_MODE=1` so the alerting service computes findings but does **not** persist, notify, publish or stream alerts — ideal while exercising rules interactively. Rules also auto-suppress findings whose evidence is clearly a detection-test harness (`from backend.detection.rules import *`, `pytest`, etc.).

### 7.2 Logs & observability

- Console output goes to stdout/stderr.
- `BARAQ_LOG_FORMAT=json` outputs JSON lines for log-shipping to a SIEM.
- `BARAQ_SYSLOG_HOST` (UDP/549) or `BARAQ_SYSLOG_TCP`… see [Streaming & SIEM](#11).
- Backend log: `logs/baraq.log` if configured via `backend/logging_config.py`.

### 7.3 Database

- **Location**: `database/baraq.db` (SQLite default). Backup this file regularly with the platform stopped.
- **Retention**: purged automatically every ~1 h; `EVENT_RETENTION_DAYS` default 30 days.
- **Model persistence**: ML metadata in `database/model_meta.json`, model bundle in `database/model.bundle.joblib`.

**Reroute to PostgreSQL** (fleet-scale): set `BARAQ_DATABASE_URL=postgresql://user:pass@host:5432/baraq` and run the additive migration script `scripts/migrate_to_postgres.py`. The schema tables auto-create on first startup; indexes follow the config.

### 7.4 Users & audit

- In-app: **Users & Audit** page lets admins add / edit / disable / reset users with role assignment.
- Everything user-related (logins, MFA changes, RBAC, alert changes) is recorded in the audit trail and viewable in the same page.
- System page → `Security audit` shows the full trail.

### 7.5 Backups

1. Stop the server (or use SQLite-safe copy when idle).
2. Copy `database/baraq.db`, `database/model_meta.json`, `database/model.bundle.joblib`, `secrets.dat`, `reports/*`.
3. Restore by running the same; secrets are bound to the machine (DPAPI), so move them together with the same Windows user/machine.

---

## 8. User Guide (Analyst)

### 8.1 Sign in

1. Open the dashboard URL.
2. Enter the username/password supplied by your admin.
3. If MFA is on, enter the 6-digit code from your authenticator app (TOTP).
4. If SSO is configured, use “Continue with SSO”.

### 8.2 The layout

- **Sidebar**: Dashboard, Alerts, Investigation, Events, Processes & Network (Telemetry), AI Assistant, Reports, Incidents, Evaluation, System, Users & Audit.
- **Top bar**: current page, security score, live status (LIVE = realtime socket connected, "15s poll" fallback otherwise), system online/offline dot, theme toggle, user menu / logout.

### 8.3 Dashboard

- **Security Score** (0–100), current risk level, event count, active alert count.
- **SCORE ring** (interactive) plus StatCards: total events, active alerts, critical/high, brute force, etc.
- **Ray**: event/alert timeline chart (Recharts), threat-category breakdown pie/donut, severity distribution, top attack types, user account activity, detection-method breakdown, live alert list (top 6).
- **Top Attack Sources** — hosts most targeted by brute force (T1110).
- **Live updates** — realtime push over WebSocket updates the score/active alerts/shots as new events & alerts arrive.

### 8.4 Alerts (`Alerts` page)

- Table of alerts with severity/status/risk, MITRE technique, rule, timestamp, score.
- **Filters**: status, severity, rule; **Search**; **Pagination**.
- **Actions per alert**: open detail → change status (Open / Investigating / Contained / Closed), add analyst note, run SOAR actions, fix alert (restore security score).
- **Bulk**: “Clear resolved/open” control.

### 8.5 Alert detail (`/alerts/:id`)

- Header: technique, `MITRE ATT&CK` link, severity/status/badges.
- **Evidence** — raw evidence payload (pre-formatted).
- **Recommended action** (from the rule config).
- **Evidence Events** — linked raw events ±30 min window (Event ID, category, ML anomaly tag, timestamp).
- **ML explanation** — SHAP/LIME-style feature attribution per linked evidence event (which signals pulled the score up/down).
- **Sidebar**: rule/MITRE/risk/confidence/created, **SOAR actions** (Isolate Host, Block Source IP, Disable Account, Kill Process, Quarantine File — with confirmation), **Threat Intel** indicators (`↻ Refresh`, Mark malicious), **Status Management** (Fix Alert / cycle statuses), **Analyst Notes**.

### 8.6 Investigation (`Investigation` page)

- Search an alert → reconstructs the **kill chain**, shows related events in a timeline graph, network context, and offers **AI analysis** (explains which signals matched).
- Attack-chain reconstruction maps spans to MITRE.

### 8.7 Processes & Network (`Telemetry`)

- Live snapshot of processes (with parent-child tree) and active TCP/listener connections.
- Sortable/searchable; refresh button; optionally send commands to matching agent endpoints (endpoint-aware agent workflow).

### 8.8 AI Assistant (`Assistant`)

- Type questions in natural language. The assistant:
  - explains an alert (like your network), 
  - summarizes the state of the system,
  - recommends remediation,
  - keeps a chat history (persisted).
- Used with the local architecture if no AI key is configured; will delegate to the BARAQ AI endpoint when configured.

### 8.9 Reports

- Generate **Executive** or **Technical** reports in PDF / HTML / JSON / CSV.
- **Report list** page: view + download any previously generated report.
- Reports incorporate system summary, alerts, and evaluation metrics where relevant.

### 8.10 Incidents (`Incidents`)

- Create an incident and link alerts; comment; assign severity; update status (open/resolved/closed). The linked alerts' data is visible from the incident.

### 8.11 Evaluation (`Evaluation`)

- Runs the detection evaluation framework against the current dataset: attack scenarios + baseline.
- After it runs: **accuracy, precision, recall, F1, FPR, detection time**, per-rule breakdown, plus a **hold-out** score on attack scenarios exclusive to the ML model.
- Useful to tune rules and validate detection quality.

### 8.12 System (`System`)

- **Overview** — host, uptime, Python, versions, collector status, disk.
- **Monitoring** — collection statistics, ML model status (trained? stale? last train time), drift signal.
- **Actions** — Trigger collection now, run ML analysis, start MR/analysis, manage model (train/analyze).

### 8.13 Users & Audit (admin)

- User table with roles; Add User; Edit (rename, change role, reset password); Enable/Disable.
- **MFA enrollment** — user can self-enroll/rotate their TOTP secret from the profile/audit screen.
- **Audit trail** — tabular history of auth + RBAC + powerful operations.

---

## 9. Multi-Endpoint Agent Ingest

Agents running on other machines can POST normalised records to the platform:

- **Endpoint**: `POST /api/ingest` with header `X-Agent-Key`.
- **Config**: `BARAQ_AGENT_KEYS` = JSON `{"agent_key": "agent-id"}` (default `baraq-agent-dev`/`agent-dev`).
- **Commands forwarding**: `GET/POST /api/commands/...` — the server can relay commands to connected endpoints (`scripts/agent.py` reference agent implementation).
- LAN deployments: use `start.bat launch` so metadata from other devices can reach you.

---

## 10. Alerting & Notifications

Notifications fire per channel, each with its own severity floor
(`BARAQ_NOTIFY_MIN_SEVERITY` for email/webhook/toast,
`BARAQ_TELEGRAM_MIN_SEVERITY` for Telegram). The recommended split is
`high` for email and `critical` for Telegram, so a phone is not trained to be
ignored. Check the routing with `scripts\show_paging_routes.py`.

| Channel | Config | Behavior |
|---|---|---|
| Webhook | `BARAQ_WEBHOOK_URL` | JSON POST payload with alert details |
| SMTP | `BARAQ_SMTP_HOST`, `_PORT`, `_USERNAME`, `_PASSWORD`, `_FROM`, `_TO` | Email alert summary (STARTTLS enforced by default) |
| Windows Toast | `BARAQ_TOAST_ENABLED` (default on) | Local taskbar notification via PowerShell helper |

Real-time dashboard notification is separate: the WebSocket pushes `alert`, `status`, `incident` messages to all connected dashboards.

---

## 11. Streaming & SIEM Forwarding

Optional outbound buses turn BARAQ into a telemetry producer:

| Sink | Enable via | Behavior |
|---|---|---|
| Kafka | `BARAQ_KAFKA_BOOTSTRAP`, topic `baraq-events` | Publish normalised events + alerts |
| Redis Streams/PubSub | `BARAQ_REDIS_URL`, key `baraq:events` | Stream events |
| Elasticsearch/OpenSearch | `BARAQ_ELASTICSEARCH_URL`, index pattern | Index events for SIEM/reporting |
| Syslog | `BARAQ_SYSLOG_HOST`, `_PORT`, `_PROTO` (udp/tcp), `_AUDIT` | RFC3164/5424 messages (optionally including audit) |

Batching: `BARAQ_STREAM_BATCH_SIZE` (25), `BARAQ_STREAM_FLUSH_SECONDS` (5), retries `BARAQ_STREAM_MAX_RETRIES` (2). Unavailable dependencies are skipped (graceful degradation).

---

## 12. REST API Overviews

Interactive docs: **`http://127.0.0.1:8001/docs`** (Swagger UI) ; openapi at `/openapi.json`.

### 12.1 Authentication

- **API key**: header `X-API-Key: <key>` (analyst/admin).
- **Session**: `POST /api/auth/login` body `{"username","password"}` → Set-Cookie `baraq_session` (httpOnly). Subsequent requests use the cookie; state changes also need `X-CSRF-Token` (see §6).
- **MFA**: `POST /api/auth/mfa/verify` with `challenge`+`code`; `/api/auth/mfa/setup`/`confirm`/`disable`.
- **SSO**: `GET /api/auth/oidc/login` → redirect flow → `/api/auth/oidc/callback`.

### 12.2 Router index

| Prefix | Purpose |
|---|---|
| `/api/dashboard/*` | summary, timeline, threat-categories, severity-distribution, attack-stats, top-attackers, user-behavior, detection-methods, rise-risk |
| `/api/alerts*` | list/get/status/notes/actions/clear |
| `/api/events*` | list, statistics (raw telemetry) |
| `/api/processes`, `/api/network` | process/network snapshots |
| `/api/investigation/*` | kill-chain, timeline context |
| `/api/reports/*` | generate / list / download |
| `/api/assistant/*` | chat, history, explain, summarize |
| `/api/evaluation/*` | run/results/latest + ML |
| `/api/system/*` | status, collect/manual, ML status/train/analyze/explain |
| `/api/endpoints*` | list endpoints, send commands, list agent commands|
| `/api/incidents*` | CRUD + link + comments |
| `/api/intel/*` | threat-intel lookups (rep/save) |
| `/api/auth/*` | login/MFA/SSO/users/audit |
| `/api/realtime/ws` | WebSocket: `hello`, `status`, `alert`, `incident` |

### 12.3 WebSocket protocol

- Open `ws(s)://HOST/api/realtime/ws?token=<session-token>`.
- Server first sends `{"type":"hello","payload":{user,role}}`.
- Further events: `alert` (new detection), `status` (summary refresh), `incident` (new/updated incident) — each with `payload` and `ts`.

---

## 13. Testing & Quality

- Test suite: pytest — run `venv\Scripts\python -m pytest` (from project root).
- Coverage includes: API and RBAC, detection rules & aggregated, evaluation/hold-out, ML prediction, retention, encryption at rest, CSRF & body-size, user auth/MFA, LDAP/OIDC SSO, agents/commands, workflows.
- Reference the existing `documentation/test_results.md` and `ml_strategy_and_validation.md` for detailed numbers and model evaluation design.

---

## 14. Troubleshooting

| Symptom | Likely cause & fix |
|---|---|
| Blank / black page after startup update | Stale `index.html` cached hydrating -> hard refresh (Ctrl+Shift+R); the backend now serves index with `no-store` and assets immutable |
| Dashboard shows “Backend Offline” | WS not connected yet; check socket connect -> scheduler running; see `BARAQ_SCHEDULER_ENABLED`; if you disabled the scheduler you won’t get live data |
| Login says "wrong credentials" even after admin setup | Use the generated password from `first_run_credentials.txt` (or `secrets.dat`), or reset the user in the DB / `Users & Audit` UI |
| API key rejected (401) | Set `BARAQ_ALLOW_DEV_KEYS=0` path: must configure `BARAQ_API_KEYS` first; otherwise provide the correct `X-API-Key` |
| Server fails to start: port already in use | Another instance running; only one uvicorn keeps itself bound |
| `[Errno 10048]` bind error | Duplicate uvicorn; close the other console or kill the process holding :8001/:8443 |
| HTTPS cert warning | Trust `certs/baraq.crt` once, or run `scripts\import_cert.ps1` to install it as root CA; or deploy a trusted cert |
| No notifications | Check `BARAQ_NOTIFY_MIN_SEVERITY`, webhook/SMTP vars, and that a high/critical alert is generated |
| Realtime LIVE not showing | Login then reload; the WS needs the session token; when not connected the page falls back to 15s polling (LIVE→“15s poll”) |
| ML "never trained" | Scheduler auto-trains once ≥ `ML_TRAIN_MIN_SAMPLES` events; trigger manually from System → Run ML analysis |

---

## 15. Glossary

- **Alert** — a correlated detection (one per rule signature, escaes with repeats)
- **MITRE ATT&CK** — framework describing attacker techniques; used to tag every alert
- **Hybrid risk** — 60% rule vulnerability score + 40% ML anomaly likelihood → 0–100
- **TTP** — Tactics, Techniques & Procedures
- **Kill-chain** — sequence of stages an attack goes through
- **SOAR** — Security Orchestration/Response (isolate, block, quarantine…)
- **TOTP** — Time-based One-Time Password (auth app)
- **RBAC** — Role-based access control
- **DPAPI** — Windows Data Protection API (per-user encryption of secret files)
- **F1 / FPR / Recall** — evaluation metrics in the Evaluation framework

---

*(c) BARAQ · End product combined guide — reviewed against the current codebase. Contact: internal documentation maintained in `documentation/` for deep-dives.)*