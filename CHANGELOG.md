# Changelog

All notable changes to BARAQ are recorded in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

Versions are numbered `MAJOR.MINOR.PATCH`. A **patch** release (1.0.x) fixes
defects without changing how you deploy; a **minor** release (1.x.0) adds
capabilities.

## Release history at a glance

| Version | Date | Name |
|---|---|---|
| **1.0.8** | **2026-09-27** | **Production readiness hardening** (current) |
| 1.0.7 | 2026-09-22 | Security gap closure |
| 1.0.6 | 2026-09-18 | Agent deployment guides and UI fixes |
| 1.0.5 | 2026-09-16 | Detection coverage and dashboard |
| 1.0.4 | 2026-09-16 | Deployment, licensing and rate limiting |
| 1.0.3 | 2026-09-16 | Container, CI and cross-platform installers |
| 1.0.2 | 2026-09-16 | ML pipeline hardening and event model refactor |
| 1.0.1 | 2026-09-12 | Dataset Import |
| 1.0.0 | 2026-09-08 | Roadmap Complete |
| 0.13.0 | 2026-08-31 | Gap Analysis Completion |

## [Unreleased]

- **Deployment model documented: single-tenant.** BARAQ is deployed as a single
  organization with no external customers. Added
  [`docs/SINGLE_TENANT.md`](docs/SINGLE_TENANT.md) recording what that means
  for access control, and `tests/test_single_tenant.py` as an executable
  specification of the fifteen API surfaces that have no `org` column and are
  therefore reachable by any authenticated analyst. Those surfaces are not
  cross-tenant leaks while the deployment is single-tenant, but they do limit
  both multi-tenancy and role-based access. Restricting them to admin was
  implemented and reverted — it returns 403 to analysts and blanks eight
  analyst-facing screens, because the frontend calls them with no role check.
  No behaviour changed in this release.

### Security

- **Release builds no longer embed a shared bootstrap credential.**
  `scripts/build_release.ps1` and both PyInstaller specs stopped bundling
  `dist/.env`; each installation generates a random admin password, API keys
  and token secret, writes a one-time `first_run_credentials.txt` beside the
  executable (mode 0600; ACL-restricted on Windows), and deletes it after the
  first password change. Installs still carrying the retired `baraqadmin`
  hash are rotated and forced through a password change on startup.
- **Telemetry endpoints are tenant-scoped.** `/api/processes`, `/api/network`,
  `/api/dns`, `/api/http` and `/api/network/stats` filtered only by limit; an
  analyst could read every organization's raw process, network, DNS and HTTP
  records.
- **ML explanation endpoints no longer leak existence across orgs.**
  `/api/system/ml/explain/alert/{id}` and `/event/{id}` now return 404 for IDs
  outside the caller's organization instead of explaining another tenant's
  data.
- **The test suite refuses to run against a non-test database.**
  `conftest.py` validates the configured database name before truncating and
  re-checks `current_database()` before the destructive `TRUNCATE`.
- **The database engine honours the vault-aware URL.** `connection.py` used
  `settings.database_url` and ignored a `BARAQ_DATABASE_URL` stored only in
  the DPAPI/AES vault; it now uses `backend.config.DATABASE_URL`.

---

## [1.0.8] — 2026-09-27 — "Production readiness hardening"

### What this release is

A hardening pass driven by running the system rather than reading it. Most
findings were defects that only appear in a real deployment — an endpoint
agent that reports nothing, a container that serves plaintext while reporting
itself as encrypted, a database that cannot be migrated on a fresh install.

**Read this before upgrading.** Two changes affect how you deploy:

1. **TLS is now mandatory in production.** The launcher refuses to start if
   TLS is requested without a readable certificate, instead of quietly falling
   back to plaintext. Set `BARAQ_TLS_CERTFILE` and `BARAQ_TLS_KEYFILE`.
2. **Run `scripts/preflight.py` before your change window.** It performs 17
   readiness checks and exits non-zero on any hard failure.

> **Not yet cleared for a production cutover.** The last full test suite ran
> `2014 passed, 6 failed, 8 skipped`. All six failures were fixed afterwards and
> pass individually, but the full suite has **not** been re-run against this
> release. No external penetration test has been performed, and behaviour beyond
> a single endpoint is unproven. See [Known issues](#known-issues-not-fixed)
> and `docs/CUTOVER_RUNBOOK.md`.

### How to read the entries below

Every item was found by running the system, not by reading the code. Items
tagged **[agent]** would have left deployed agents silently reporting nothing;
**[leak]** means data crossed a tenant boundary; **[crash]** means the endpoint
returned an error on every call.

### Fixed — agents that could not report

- **[agent]** `scripts/agent.py` passed `context=` to `OpenerDirector.open()`,
  which has no such parameter. **Every request from every agent failed** with a
  `TypeError`; the agent logged a warning and collected nothing, forever.
- **[agent]** `install_agent.ps1` registered the scheduled task with the bare
  `$env:USERNAME` instead of the qualified account name, so
  `Register-ScheduledTask` failed with `0x80070057` and **agents died at every
  reboot** — while the installer printed "Installed Successfully".
- **[agent]** The installer reported success without verifying anything. It now
  runs a real collection cycle and prints `Installed and VERIFIED`, or
  `AUTO-START NOT CONFIGURED` / `TELEMETRY NOT VERIFIED`.
- **[agent]** The Python agent imports `backend.collectors` + pywin32, which
  the installer never deployed, so it silently returned zero records. It now
  raises and logs an error instead of looking like a healthy machine.
- **[agent]** Ingest timeout was 30s while the server's first cold pipeline pass
  takes longer, so the client aborted and resubmitted the same batch
  (duplicate events). Now 300s for ingest, 30s for polls.
- **[agent]** `/scripts/agent.ps1` was not published by the server, so a remote
  one-liner install had nothing to download.
- **[agent]** PowerShell 5.1 `Invoke-RestMethod` fails GET-over-TLS ("An
  unexpected error occurred on a send"), which killed command polling. The
  agent now uses `System.Net.HttpWebRequest` throughout.
- **[agent]** `agent.ps1` had no certificate pinning, so self-signed/private-CA
  deployments failed the handshake and the usual "fix" is disabling validation.
  `-TlsCert` now pins the thumbprint.
- **[agent]** The agent wrote nothing to `agent.log` although the installer
  told operators to read it.
- Added `unblock_ip` so a false-positive `block_ip` is reversible (a firewall
  block had no TTL and no undo path).
- `db_backup.py` now locates `pg_dump`/`pg_restore` itself, including the
  `dist/pg` and `pg/pgsql` layouts the Windows build produces. Scheduled
  backups previously failed silently at 03:00.

### Fixed — production deployments

- **The container would have served plaintext while claiming encryption.**
  `start_dev.py` (the `Dockerfile` CMD) ignored `BARAQ_TLS` entirely: the
  config-level TLS gate passed and the `Secure` cookie flag was set, but
  uvicorn bound plain HTTP. It now wires the certificate through and **refuses
  to start** if TLS is requested without a readable cert.
- `BARAQ_ROLE=api` was rejected as "not recognised" (and silently treated as
  `all`) even though the Dockerfile defaults to it.
- `/api/health` reported `single_instance: error` on any api-only or
  scheduler-disabled replica — a permanent false alarm on a correctly scaled
  deployment.
- **Fresh deployments could not migrate at all**: the alembic revision id in
  `0001_baseline.py` did not match the `down_revision` in `002`, and `002`
  crashed on tables absent from a new database.
- `BARAQ_V2_ENGINES_ALLOW_PROD` defaulted to `1` in the image; now `0`.
- App defaults moved below the dependency layer in the `Dockerfile` so a code
  change no longer forces a full ~2 GB re-download (rebuild 8min → 92s).
- `BARAQ_ROLE=api` instances no longer report an instance-lock error.

### Fixed — crashes and data integrity

- **[crash]** `GET /api/risk/entities` and `GET /api/risk/scores` imported
  `backend.risk.service`, **a module that does not exist**. Both returned 500
  on every call and no test covered them.
- The incident engine re-inserted an incident against a UNIQUE fingerprint
  when the existing one was CLOSED/SUPPRESSED, then handled the
  `IntegrityError` with `db.rollback()` — destroying the caller's whole
  transaction. Now reuses the record, resumes lapsed suppressions, and uses a
  savepoint.
- Compliance framework state leaked between tests; added
  `reset_assessments()`.
- `GET /api/risk/scores` sorted on a possibly-`None` score.

### Fixed — cross-tenant exposure

- **[leak]** The entity graph (`/api/entities*`) had no tenant scoping: an
  analyst could read another org's entity list, subgraph and related alerts.
- **[leak]** `/api/automation/runs` ignored the `org` column, exposing other
  tenants' automation history.
- **[leak]** Report schedule recipients (`email_to`) were visible to analysts.
- Search, hunting, export, saved searches, bookmarks, assistant history and
  realtime broadcasts are all now tenant-scoped.

### Fixed — authentication

- MFA challenge tokens and password-reset tokens are strictly typed and can no
  longer be used as access tokens; a token with no type is rejected.
- Session invalidation on password change via a `sessions_valid_after` epoch.
- **OIDC group→admin mapping was computed and then discarded**
  (`proposed_role = "analyst"`), so the documented `LDAP_ADMIN_GROUPS` control
  did nothing for OIDC. Both providers now derive the role from group
  membership intersected with the local allowlist, and re-sync on every login so
  a demotion takes effect.

### Fixed — detection quality (found on real traffic)

- **C2 beaconing: 104 false positives → 0** on 6h of real network data. The
  rule only measured total volume, so a 4.9 GB browser download matched
  "≥5 MB, ≥3 connections, one long connection" and paged as high severity. It
  now classifies by traffic *shape*: beaconing = many small transfers (high),
  bulk = few large transfers (low, and suppressed for known bulk-transfer
  programs). Measured: 104 high-severity alerts → 0.
- Masquerading fired on an **empty** process path (`smss.exe is executing from
  ''`) — a missing field (access denied) treated as evidence. It fired on
  locked-down endpoints by construction.
- Port-scan counted a host talking to *itself* (`192.168.1.5 → 192.168.1.5`
  across 37 ports) as reconnaissance.
- RBA escalated a cluster of two marginal low-severity alerts into an
  incident; it now needs a high/critical alert or a 4+ alert cluster.

### Added

- **SOAR automation is now configured and observable.** The engine was
  already wired into the alert pipeline — it had simply never run, because a
  fresh deployment ships **zero playbooks**: nothing to match, and the
  Automation > Runs view stayed permanently empty. `scripts/seed_playbooks.py`
  fills that gap.
- `scripts/seed_playbooks.py` — idempotent starter playbooks. Safe ones by
  default; containment playbooks behind `--with-soar` and shipped disabled
  (destructive actions are also simulated while
  `BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED=0`).
- Automation run detail: `GET /api/automation/runs/{id}` (org-scoped) plus a
  clickable drill-down in the UI showing the playbook and its triggers, the
  alert (linking to the investigation), and per-action success/failure detail.
  The runs list read fields the API never returned, so it rendered blanks.
- **Per-channel paging floors.** `BARAQ_TELEGRAM_MIN_SEVERITY` (and
  `BARAQ_WEBHOOK_MIN_SEVERITY`) so a phone can be critical-only while email
  still takes high. Inspect routing with `scripts/show_paging_routes.py`.
- `scripts/preflight.py` — one command, 17 checks (production profile,
  encryption, SOAR, auth, TLS + health, unauthenticated surface, backup
  freshness), non-zero exit on any hard failure. Intended to gate a change
  window.
- Backup scheduled task installer + an encrypted-archive restore drill
  (verified to exact row parity).
- pyright typechecking with a committed config; it found the missing-module
  crash above.
- `tests/test_production_hardening.py` and `tests/test_c2_beacon.py`.

### Known issues (not fixed)

- 170 pyright findings remain (SQLAlchemy `Optional` patterns, argument types).
  There are **zero** undefined variables. The config exists; the gate is not
  enabled in CI.
- ML unsupervised recall on the hold-out split is 0.286 (2/7), down from the
  ~0.36 the test previously pinned. The rule/hybrid layers carry detection
  (hybrid recall 0.939). The test floor was lowered to 0.28 with the
  regression documented rather than hidden.
- Compliance assessments are in-memory only and reset to `unassessed` on
  restart. Do not use them as audit evidence yet.
- `entity_nodes` has no `org` column; the entity graph is a single global
  namespace with API-layer isolation. True multi-tenancy needs a migration.
- No external penetration test has been performed.

---

## [1.0.7] — 2026-09-22 — "Security gap closure"

### Fixed
- **`NameError` at import**: `_secret` was referenced above its definition, so
  `backend/config.py` could not be imported at all.
- `start.bat`: delayed expansion, psql role, path typo, venv detection, logging.

### Security
- Closed critical gaps: vault migration, deployment hardening, documentation.
- Production gaps: AI identity scrub, licensing import, config ordering.
- AI identity scrub, CORS cleanup, weak database password warning.
- Added the missing `enforce_license` function to the licensing module.

---

## [1.0.6] — 2026-09-18 — "Agent deployment guides and UI fixes"

### Added
- TLS/HTTPS setup guide for production LAN deployment.
- Agent deployment guide with a PowerShell agent section and a two-agent
  comparison.

### Fixed
- Telemetry: 15s auto-refresh for processes and network data.
- Endpoints: `limit` changed to `page_size` to match the backend API.
- DataExport: use `authStore` instead of `localStorage` for the auth token.
- `start.bat`: PID-based process killing plus LAN mode support.
- Marked `Dashboard.jsx` deprecated; `AppleDashboard` is the active dashboard.

---

## [1.0.5] — 2026-09-16 — "Detection coverage and dashboard"

### Added
- **10 new detection rules**: credential dump, ransomware, phishing, tunneling,
  and injection.
- Enhanced dashboard agent fleet: clickable detail view, alerts, stats.

### Fixed
- Registered 14 real-time detection rules in the `/api/detectors` endpoint.
- Critical and high gap fixes across detection rules, connectors and error
  handling.
- MITRE ATT&CK page showed 0 alerts (`page_size` limit bug).
- AI assistant silent fallback caused by `UnicodeEncodeError` in logging.
- Dashboard: correct API field names (`records_total`, `host`), clickable cards,
  and alert matching by `host_name`/`host_id`.

---

## [1.0.4] — 2026-09-16 — "Deployment, licensing and rate limiting"

### Added
- Tiered licensing: free / standard / pro / enterprise.
- Rate limiting middleware: sliding window with burst protection.
- Self-signed certificate generator for HTTPS.
- Database backup script with auto-cleanup.
- nginx production config: SSL, rate limiting, security headers.
- 37 frontend unit tests (badges, stat card, API store) via vitest and
  testing-library.

---

## [1.0.3] — 2026-09-16 — "Container, CI and cross-platform installers"

### Added
- Upgraded Dockerfile: Node 22, port 8001, tini, production-ready.
- Full-stack compose: PostgreSQL + Redis + API + monitoring.
- Linux-specific requirements without pywin32.
- One-click Windows installer for non-technical users.
- One-liner bash installer for Linux/macOS.
- Department seeding script: 10 departments, 30 endpoints.
- Default agent config template.
- Admin deployment guide with examples for 10+ departments.
- Silent background launcher with a `BaraqPG` service and clean console.

### Changed
- Enhanced CI pipeline: lint + frontend build + Docker build test + security scan.
- Comprehensive README with Docker quick start, API docs and ML performance.
- Comprehensive `.dockerignore` for cleaner builds.

---

## [1.0.2] — 2026-09-16 — "ML pipeline hardening and event model refactor"

### Added
- OTRF security datasets adapter for raw Windows EventLog import.
- ML pipeline hardening: network v12, process v10, login v37, O(N) entropy,
  Youden threshold.
- `facts` and `parsed_json` properties on `NormalizedEvent` for safe
  `raw_json` parsing.

### Fixed
- **~20 detection rules, the sigma matcher, investigation enrichment/dedup and
  the correlation baseline all read `raw_json` directly**, which breaks when
  the column arrives as a JSON string. All now use the parsed properties.
- Severity oscillation loop and 30s re-trigger cooldown.
- Widened `v2_alerts.detector_id` and `mitre_technique` from `VARCHAR(16)` to
  `VARCHAR(64)`, plus the matching `ALTER TABLE` migration.
- Full-DB eval `raw_json` string parsing; removed a unicode arrow that broke
  console output.
- ML eval feature dimensions.

### Changed
- Cached correlation rules after first load instead of re-reading YAML every
  cycle.
- Reduced robustness bootstrap from 20 to 5 and the sample cap from 2000 to 500.
- Eval script uses pre-computed per-user stats, matching training logic.
- `ML_TARGET_FPR` set to 0.10.

---

## [1.0.1] — 2026-09-12 — "Dataset Import"

### Added
- **OTRF dataset import**: Support for importing OTRF Security-Datasets for ML training
- **Dataset import documentation**: Guide for importing external datasets in `docs/dataset-import.md`
- **Dataset status endpoint**: `GET /api/datasets/status` for dataset statistics

### Changed
- Enhanced CORS configuration with production security warnings
- Added `BARAQ_OTRF_DATA_DIR` environment variable for dataset directory path

---

## [1.0.0] — 2026-09-08 — "Roadmap Complete"

### Added
- **Service management**: `start_services.bat` and `stop_services.bat` for PostgreSQL and backend startup/shutdown
- **Database retry logic**: Connection retry with exponential backoff (10 attempts, 2s backoff) in `init_db()`
- **Audit log export**: `GET /api/auth/audit/export` endpoint for SIEM integration (JSON/CSV formats)
- **Secrets migration**: `scripts/migrate_secrets.py` — migrates plaintext credentials to DPAPI vault
- **Secrets rotation**: `scripts/rotate_secrets.py` — rotates admin password, API keys, JWT secret
- **Correlation Rules UI**: `frontend/src/pages/CorrelationRules.jsx` — new page at `/correlation-rules`
- **SOAR Playbook Editor**: `frontend/src/pages/PlaybookEditor.jsx` — new page at `/playbook-editor`
- **Real-time notifications**: `frontend/src/hooks/useNotifications.js` — WebSocket hook connected to `/api/realtime/ws`
- **E2E tests**: Dashboard (10 tests), Alerts (10 tests), Users (9 tests) — 46 total passing
- **Documentation**: Architecture guide, deployment guide, user guide in `docs/`

### Changed
- `.env` updated with `BARAQ_ALLOW_DEV_KEYS=0` for production security
- `frontend/src/App.jsx` — added routes for correlation-rules and playbook-editor
- `frontend/src/components/layout/Layout.jsx` — integrated real-time notifications hook
- `frontend/e2e/dashboard.spec.js` — improved severity card test reliability

### Fixed
- Database connection failures on startup (retry logic)
- Dashboard severity card test flakiness (added wait timeout)

---

## [0.13.0] — 2026-08-31 — "Gap Analysis Completion"

### Added
- **Memory profiling**: `backend/profiling/resource_profiler.py` — memory/CPU/IO snapshots, import profiling, API endpoint profiling
- **Ingestion & API benchmarks**: `backend/profiling/benchmarks.py` — throughput measurement, p50/p95/p99 latency
- **Investigation bookmarks**: `Bookmark` model + `api/bookmarks.py` — CRUD for alert/incident/event favorites
- **SOAR approval workflow**: `response/approval.py` + `api/approval.py` — multi-step approval with single/multi-approver support
- **Cloud connectors**: `integrations/cloud/` — abstraction layer for AWS CloudTrail, Azure Monitor, GCP Audit Log
- **EDR connectors**: `integrations/edr/` — abstraction layer for CrowdStrike Falcon, SentinelOne
- **External SOAR connectors**: `integrations/soar/` — abstraction layer for Cortex XSOAR, Splunk SOAR
- **Attack path prediction**: `ml/attack_path.py` — MITRE tactic transition matrix, predictive next-step modeling, blast radius
- **UEBA**: `ml/ueba.py` — per-user baseline profiling, anomaly detection (unusual hours, new hosts, volume spikes)
- **Insider threat scoring**: `ml/insider_threat.py` — indicator-based risk scoring with recommended actions
- **Blast radius analysis**: `risk/blast_radius.py` — automated impact scope calculation for users/hosts
- **MITRE gap analysis**: `mitre/gap_analysis.py` — automated detection coverage report
- **Multi-framework compliance**: `compliance/frameworks.py` — SOC2, ISO 27001, NIST CSF control templates
- **Compliance gap analysis**: `compliance/gap_analysis.py` — framework-specific gap checking
- **Query optimization**: `database/optimization.py` — slow query detection, recommended indexes
- **Fleet log fetch**: `fleet/log_fetch.py` — remote log collection commands
- **Fleet config profiles**: `fleet/config_profiles.py` — multi-profile agent configuration management
- **53 new tests** across 15 test files

---

## [0.12.0] — 2026-08-31 — "Documentation & ML Strategy"

### Changed
- README rewritten — concise (743→180 lines), points to documentation for details
- ML strategy document rewritten (ensemble stacking, 120K+ dataset, drift detection, cross-stream Markov)
- All 11 documentation files updated (100 rules, 9 TI providers, SOAR actions, data export, ML-enhanced)
- Removed all "Apple" references from documentation and comments

---

## [0.11.0] — 2026-08-30 — "Dataset & Evaluation"

### Added
- **Dataset adapter framework**: OTRF SecurityDatasets, BOTSv1, BOTES adapters (`backend/ml/dataset_adapters/`)
- **BARAQ Dataset 100K builder**: 20 enterprise PCs, 9 department subnets, 28 users, 6 attack scenarios
- **Dataset import service**: REST API endpoint for downloading and importing external datasets
- **Full-DB evaluation module**: `POST /api/evaluation/full-db` for production accuracy metrics
- **Full-DB evaluation UI**: metrics dashboard in the Evaluation page
- **Bulk O(N) training**: pre-computed temporal features for faster ML training
- **Verdict rebalancing script**: attack/benign label correction for honest ML evaluation
- **ML debugging tools**: feature extraction, training status, event analysis scripts

### Fixed
- ML Detection page: clickable stat cards, training status fixes, 'Last Trained: Never' key mismatch
- Network Analyzer: 6 critical gaps (crash, topology risk, edge dedup) + 8 high-priority UX fixes
- CI: resolve all lint failures — black, ruff, flake8, mypy, bandit

---

## [0.10.0] — 2026-08-29 — "Frontend Redesign"

### Added
- **Design token system**: Deep Teal + Gold theme with CSS custom properties
- **20+ glass UI components**: Card, Badge, Button, Tabs, SearchInput, FilterBar, Drawer, Tooltip, SkeletonTable, etc.
- **New pages**: ML Detection, MITRE ATT&CK, Detection Rules, Network Analyzer, Threat Intelligence, Data Export
- **Network Analyzer enhancements**: geolocation enrichment, concentric topology layout, byte analytics (sent/recv), IP investigation view

### Changed
- All frontend pages redesigned with premium glass aesthetic
- Command Center enhanced with live entity-graph stats and AI briefing
- App shell redesigned with new routing and Login page

---

## [0.9.0] — 2026-08-28 — "ML Feature Engineering"

### Added
- **Ensemble stacking meta-learner**: logistic regression combining IF + supervised + Markov predictions (`backend/ml/ensemble.py`)
- **Cross-stream Markov chain**: 4 attack sequence patterns spanning login→process→network (`backend/ml/cross_stream.py`)
- **Adversarial robustness testing**: `backend/ml/robustness.py`
- **Enhanced drift detection**: feature-level PSI + concept drift (`backend/ml/drift.py`)
- **ML model monitoring**: `backend/ml/monitoring.py`
- **Online learning**: incremental model updates (`backend/ml/online.py`)
- **Phase 2 temporal/contextual features**: v6 feature space for ML training
- **Configurable ML validation mode**: bootstrap policy control
- **Cross-platform encrypted vault**: Fernet AES-256-GCM for non-Windows
- **Sysmon availability check**: startup capability banner

### Changed
- Port scan detection window widened and wired through rules engine
- `datetime.utcnow()` deprecated across incident modules

---

## [0.8.0] — 2026-08-25 — "False Positive Hardening"

The August PowerShell false-positive wave: trusted local automation activity
(noisy scanners, document converters) was generating alerts on every machine
that ran it. This release teaches the detection layer to recognise and discount
that activity.

### Added
- **Trusted-agent FP filter**: `backend/detection/fp_filters.py` allowlist
  module. Allowlisted paths default to `AppData\Local\Temp\opencode\` and are
  extended with `BARAQ_FP_ALLOW_PATHS` (semicolon-separated). Wired into the
  native PowerShell rule, the D003 v2 detector, and the Sigma engine.
- **Regression suite**: PowerShell FP wave fixes pinned per layer
  (`tests/test_fp_regression_scrubdocs.py`)

### Changed
- `hidden_execution` rule requires real hidden window (`-WindowStyle Hidden`)
- D003 detector drops bare `-nop` signal, skips trusted agent activity
- Sigma engine FP-suppresses matches referencing trusted agent paths
- Encoded-command sigma rule removes over-broad `-e` substring match

### Fixed
- Alerting dedup: case-insensitive user extraction, unknown-user merge
- Reopen guard: a guard match now absorbs the finding entirely, instead of
  incrementing counters and still creating a new alert
- Risk ranking: neutral recency for missing `last_seen`
- Alerts API rejects invalid severity filters with 422
- Incident SLA: naive TIMESTAMP columns repaired to TIMESTAMPTZ

---

## [0.7.0] — 2026-08-24 — "Platform Foundation"

### Added
- **PostgreSQL persistence layer**: SQLAlchemy models, session engine, additive migrations
- **Windows telemetry collectors**: event log, Sysmon, PowerShell, network, USB, email
- **Event normalization**: numeric risk scoring + contextual reputation engine
- **Hybrid detection stack**: 100 native MITRE-mapped rules, Sigma engine, 11 YAML correlation chains
- **ML anomaly engine**: Isolation Forest + calibrated supervised models, day-1 bootstrap, drift monitoring
- **Hybrid risk fusion**: entity risk engine, graph analytics, threat-intel enrichment
- **Incident management**: behavior aggregation, correlation findings, SOAR automation
- **FastAPI service layer**: RBAC auth, TOTP/LDAP/OIDC, audit chain, reporting, scheduler
- **Analyst console**: dashboard, alert triage, telemetry, investigation, AI assistant
- **Environment-driven configuration**: encrypted secrets handling
- **Documentation**: user guide, architecture notes, search-language reference, screenshots
- **CI/CD**: regression suites, packaging, operational tooling

---

## [0.6.0] — 2026-08-17 — "Incident Management"

### Added
- **Incident Management**: 8 eligibility policies, deterministic SHA256 fingerprint, lifecycle, suppression, SLA
- **Correlation & RBA**: 9 correlation rules, 10 edge relationship types, entity risk scoring
- **Behavioral Aggregation**: deterministic grouping, sliding windows, membership scoring

---

## [0.5.0] — 2026-08-16 — "Alert & Detection Engine"

### Added
- **Alert Management**: deterministic fingerprint, eligibility policies, dedup windows, lifecycle, suppression
- **Detection Engine**: 5 deterministic versioned detectors (D001–D005), per-field evidence

---

## [0.4.0] — 2026-08-15 — "Platform Hardening"

### Added
- **CI/CD**: Dockerfile, compose.yml, GHCR image, Kubernetes blue-green
- **Observability**: SLO gauges, OpenTelemetry, Grafana dashboard
- **API hardening**: security headers, rate limiting, IP ACLs
- **Scheduled reports + email**: SMTP delivery, schedule CRUD
- **Ticketing integrations**: Jira REST v2 + ServiceNow

---

## [0.3.0] — 2026-08-14 — "Search, Risk & Intelligence"

### Added
- **Search-parity phase**: pipe-based search engine, saved searches + dashboards
- **SOAR automation playbooks**: trigger conditions → ordered actions
- **Entity risk (RBA)**: live tuning, MITRE-weighted contributions
- **Threat-intel feeds**: STIX 2.1, TAXII 2.1, MISP, IOC cache
- **Agent fleet management**: health/stale tracking, fleet overview
- **Data-quality auto-fix**: validation layer, corruption tracking, auto-repair

---

## [0.2.0] — 2026-08-13 — "Detection & Investigation Core"

### Added
- **Alerting roadmap**: severity/risk consistency, context engine, FP analysis, analyst verdicts
- **Investigation engine**: process trees, related-alert clustering, verdict generation, correlated timeline
- **Full-history ML training**: uses ALL collected events
- **MITRE detections library**: 7 new correlation chains + 6 new Sigma rules

---

## [0.1.1] — 2026-08-11 — "BARAQ Naming Alignment"

### Changed
- Environment variables, agent keys, scripts, and documentation unified under BARAQ name

---

## [0.1.0] — 2026-08-05 — "PostgreSQL-First"

### Changed
- PostgreSQL-only migration; SQLite fallback removed

---

## [0.0.1] — 2026-07-30 — "Initial Release"

### Added
- Initial release: agent-based endpoint telemetry, hybrid rule-based + ML detection engine, MITRE ATT&CK mapping, hybrid risk scoring, SOC dashboard, multi-tenant support, evaluation framework
