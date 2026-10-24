
> **ARCHIVED - DO NOT FOLLOW.** This document predates the 2026-09 production
> hardening pass and describes behaviour that no longer exists (plain HTTP
> servers, the Python-only agent, `POST /api/automation/run`, dev API keys in
> production). Current documentation:
>
> - Deployment / cutover: `CUTOVER_RUNBOOK.md`, `PRODUCTION_DEPLOY.md`
> - Agents: `agent-deployment.md`, `agent_fleet.md`
> - TLS: `TLS_PRODUCTION.md`, `tls-setup.md`
> - Security: `../SECURITY.md`
> - Backups: `backup_restore.md`
> - What changed, and what is still broken: `../CHANGELOG.md`

# BARAQ â€” Central University Deployment Guide

This guide covers the supported deployment of BARAQ as the central
console for a multi-tenant university consortium: one central server, several
campuses ("orgs"), analyst accounts that only see their own campus traffic,
admins that see everything, and campus agents shipping host telemetry over
HTTPS.

Reference topology: **1 central Windows server + 1..N hosts per campus**.

---

## 0. Portable deployment (no Python / Node / system PostgreSQL needed)

The recommended way to stand up a Windows server fast. Two equivalent
options are shipped in `dist\`:

| Option | Artifact | Requires | Notes |
|--------|----------|----------|-------|
| A. Installer | `dist\BARAQ-Setup-1.0.0.exe` (Inno Setup) | Windows 10/11 64-bit, ~1 GB free | Installs the frozen server, bundled PostgreSQL and scripts to `Program Files\BARAQ` (cluster data under the user's `AppData\Local\BARAQ\postgres`); creates start-menu shortcuts; uninstaller removes app + autostart task, keeps the DB cluster and vault |
| B. Portable | `dist\BARAQ.exe` + `dist\pg\` + `dist\scripts\` | Windows 10 1809+ | Whole folder is copy-portable; run `BARAQ.exe` or `scripts\provision_postgres.ps1` from the editor of choice |

The bundled build is path-portable: the frozen server locates its data,
scripts, certs and the `pg\` toolkit relative to its own executable
(`sys.executable`), never hard-coded drive letters. Environment config
(`BARAQ_PORT`, `BARAQ_DATABASE_URL`, TLS settings, â€¦) is read from
`.env` next to the exe if present; otherwise defaults apply (port 8001,
`pg\data` cluster on 127.0.0.1:55432).

Steps (option A) - one click:

1. Copy `BARAQ-Setup-1.0.0.exe` to the server (or a USB drive / share) and
   double-click it. Accept the UAC prompt. Two setup pages list optional
   tasks - both default to ON and you can just click through:
   - **Provision local PostgreSQL** (bundled - installs from the payload,
     nothing to download unless the binaries are missing)
   - **Register BARAQ to start automatically** (logon task, or NSSM service)
2. That's it. The installer, in order: lays out `Program Files\BARAQ`
   (server + bundled PostgreSQL binaries), creates the portable cluster
   under `%LOCALAPPDATA%\BARAQ\postgres` (data REALLY stays there, per
   user, never in Program Files), starts it on 127.0.0.1:55432, creates
   the `baraq` role + `baraq` database and writes `BARAQ_DATABASE_URL`
   into `Program Files\BARAQ\.env`, registers the autostart task and
   launches the backend. If the "launch now" checkbox appears at the end
   (only when autostart was deselected) it starts the console directly.
3. (Recommended) copy `verify_install.cmd` from `dist\` next to the
   installer and run it once after setup: it checks the installed files,
   the PostgreSQL cluster on 55432, the backend on 8001, the health
   endpoint, the seeded admin login and the autostart task, and prints a
   pass/fail summary.

First boot with an empty database seeds the application role, a TOTP-less
`admin` super-user and a bootstrap API key, all printed to the console log
â€” capture and store them (the API key also lives in `data\secrets.dat`,
the app vault). After provisioning, follow the
first-run checklist in section 3 (change the admin password, enroll MFA,
create analysts per campus). TLS enforcement is identical to source runs:
use `BARAQ_ENV=production` + the `start_pg_server.cmd` HTTPS launcher,
or the documented self-signed setup, before putting agents on it.

Upgrade / reinstall: the installer is idempotent â€” re-running it over an
existing `%LOCALAPPDATA%\BARAQ\postgres` cluster leaves the operator data
untouched; if the new install finds no `BARAQ_DATABASE_URL` in `.env` it
rotates the `baraq` role password and writes a fresh one. Uninstall
removes the app and the autostart task but keeps the database cluster and
vault (back up first when they matter, see
`documentation/backup_restore.md`).

## 1. Prerequisites (central server)

Installation prerequisites apply to **source runs** (`start.bat`) only;
the portable build (section 0) bundles Python, Node build output and
PostgreSQL.

| Requirement | Detail |
|-------------|--------|
| OS          | Windows 10/11 (Windows Server 2019+ recommended) |
| Python      | 3.11+ on PATH â€” source runs only |
| Node.js     | 18+ (one-time dashboard build) â€” source runs only |
| PostgreSQL  | 16+ on 127.0.0.1:55432, or use `scripts\download_postgres.ps1` + `scripts\pg_setup.ps1` to provision a portable `pg\data` cluster with no system install |
| Network     | Inbound TCP **8443** (HTTPS) from agent hosts and analysts |
| Storage     | ~1 GB headroom + growth per fleet host |

## 2. Install the central server (one time)

```powershell
start.bat secure lan
```

What this does:

- creates `venv`, installs dependencies, builds the dashboard (first run only),
- generates a self-signed TLS certificate in `certs\` (SANs = localhost + all
  LAN IPv4 addresses; rotate by deleting `certs\baraq.thumbprint` and rerunning),
- opens TCP 8443 in the Windows Firewall (needs an admin shell),
- starts uvicorn with `--ssl-certfile certs\baraq.crt --ssl-keyfile certs\baraq.key`
  and serves the console at **https://<server-ip>:8443**.

HTTPS is the standard deployment path. Plain `start.bat` (http, :8001) is for
local development only â€” campus telemetry must never cross the network
unencrypted. For a production server, run it as a Windows service instead
(see `scripts/install_service.ps1` and `documentation/windows_service.md`).

### 2a. Provision PostgreSQL (required â€” no SQLite fallback exists)

BARAQ is PostgreSQL-only. Before the first backend start, provision the
cluster and app credentials (idempotent â€” safe to re-run):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\provision_postgres.ps1
```

This reachability-checks the cluster (default `127.0.0.1:55432`), creates the
application role `baraq` (generated password) and database `baraq`, and
writes `BARAQ_DATABASE_URL` into `.env`. The backend then runs entirely
against PostgreSQL â€” the SQLite fallback was removed. Migration of a legacy
SQLite dataset is still possible via `scripts\migrate_to_postgres.py`.

### 2b. Daily encrypted backups

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_backup_task.ps1 -Time 03:00
```

Registers a daily `db_backup.py backup --encrypt --keep 14` scheduled task.
Procedure and restore drill: `documentation/backup_restore.md`.

## 3. First-run security checklist

1. **Change the admin password** - open `first_run_credentials.txt` next to
   the executable, log in as `admin`, and change it immediately. The file is
   deleted after the change. Installs that still use the retired shared
   `baraqadmin` value are marked `must_change_password` on startup and rotate
   it automatically.
2. **Enroll admin TOTP 2FA** â€” with `BARAQ_ENFORCE_ADMIN_MFA=1` (production
   default), admin API features stay locked until every admin has a TOTP
   second factor (Account > Security in the console).
3. **Create analysts** â€” one per campus; the user's `org` must match the
   campus org id exactly (e.g. `univ-a`).
4. **Create global admins** â€” for operators who must see every campus.
5. Optionally wire alerting: webhook / SMTP env vars (see README).
6. Back up `secrets.dat` and the database (see `documentation/backup_restore.md`).

## 4. Provision campuses (orgs) and agents

All agent keys are generated on the server, stored in the DPAPI vault
(`secrets.dat`), and host launch configs are written to `agent_configs\`.
Keys are shown **once** at provisioning time â€” distribute them over a
trusted channel and treat them as secrets.

Single host, with tenant:

```powershell
venv\Scripts\python scripts\provision_agent.py add ws-lib-01 https://soc.example.com:8443 --org univ-a --tls-cert certs\baraq.crt
```

Whole campus at once (recommended for on-boarding a university):

```powershell
venv\Scripts\python scripts\provision_university.py setup univ-a https://soc.example.com:8443 ^
    --org-name "University A" --hosts ws-lib-01,ws-lib-02,ws-chem-04,prn-lab-07 ^
    --tls-cert certs\baraq.crt

venv\Scripts\python scripts\provision_university.py list          # campuses + hosts
venv\Scripts\python scripts\provision_university.py revoke-org univ-a
```

The script writes `agent_configs\univ-a-manifest.json` with one launch line
per host. **Restart the BARAQ console** so the new keys and the org
map are loaded (`BARAQ_AGENT_KEYS` / `BARAQ_AGENT_ORGS` are read at
startup).

The org map is what makes isolation end-to-end: detection rules and every
view in the console only see a campus's own events and alerts, and Prometheus
metrics are labeled per campus.

## 5. Deploy the agent on each campus host

On each host: copy the server certificate `certs\baraq.crt` from the
central server, then run the launch line from the manifest:

```bat
copy \\soc\share\baraq.crt .\baraq.crt
python scripts\agent.py --server https://soc.example.com:8443 --key "<host-key>" --tls-ca .\baraq.crt --interval 15
```

Hosts without Python can run the packaged fleet agent: copy
`dist\agent\<host-name>\` (a PyInstaller build with the launch line baked
in) and run `agent.exe --install` from an admin shell to register it as an
always-on Windows service, `--uninstall` to remove it. `--verbose` logs
each ship cycle. In both modes the agent re-registers with the server as
an "endpoint" automatically; volume counters in the console confirm the
pipeline end-to-end.

Make the agent auto-start with the host (startup scheduled task or service).
`--no-verify` exists for isolated labs only.

Verify in the console: **System > Connected Endpoints** shows the host after
its first cycle (`online`, volume counters climbing), attributed to the
campus org.

## 6. Console of operations per campus

- Analysts of campus A only see campus A endpoints, alerts, events,
  incidents and dashboard numbers.
- Admins see everything and can scope the dashboard to a campus.
- Cross-org access returns 404 â€” it never leaks data.

## 7. Fleet monitoring (optional, Docker)

```powershell
docker compose up -d prometheus grafana
```

`deploy\grafana\dashboards\baraq-overview.json` ships with the
**Fleet per Org** row: per-campus ingestion rates, alert counts by
org+severity, reporting hosts, open alerts. The `org` template variable
focuses the view on one campus.

## 8. Backups & lifecycle

- DB + vault backup schedule: see `documentation/backup_restore.md` (daily
  task installed with `scripts\install_backup_task.ps1`).
- Cert rotation: delete `certs\baraq.thumbprint`, re-run the server
  launcher, redistribute `baraq.crt` to clients/agents.
- Key rotation: `revoke` the host, `add` it again, update the launch line,
  restart the service.

## 9. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Analyst sees wrong (or no) data | the user's `org` must equal the campus org id |
| Agent never connects | open TCP 8443; agent must use `https://` and `--tls-ca <server cert>` |
| New key returns 401 | restart the service â€” keys are loaded at startup |
| Browser cert warning | `scripts\import_cert.ps1` on the client (or `-Machine` as admin) |
| Prometheus scrape 401 | use the bearer key from `deploy\prometheus\.my-scrape-key` |
| Agent ships nothing | check `--interval`, host collectors, agent log lines |
## 10. CI-CD & blue-green deployment (roadmap 5.1)

### CI pipeline

The repository ships a GitHub Actions workflow (`.github/workflows/python-package.yml`):
lint (flake8 syntax errors), the full test suite against a real PostgreSQL 16
service, and - on version tags only - a `docker-image` job that builds the
Linux API image (`Dockerfile`) and pushes it to GHCR
(`ghcr.io/<owner>/SentinelSOC:<tag>`). The image targets the stateless roles:

* `BARAQ_ROLE=api` - uvicorn serving the FastAPI app
* `BARAQ_ROLE=scheduler` - `python -m backend.scheduler_service`

Collectors stay Windows-native on the endpoints; the Linux image never runs them.

### Running the API image locally (Docker)

```powershell
docker compose --profile api up -d --build
curl.exe http://localhost:8001/api/system/status
```

`BARAQ_DATABASE_URL` inside the container defaults to the host PostgreSQL
(`host.docker.internal:55432`) - override it in `.env` as usual.

### Blue-green API rollouts (Kubernetes)

`deploy/k8s/blue-green/baraq-blue-green.yaml` defines two identical API
Deployments (`baraq-api-blue` / `baraq-api-green`) plus a `baraq-api` Service
that routes to the active release via a `release` label. The scheduler and
Postgres keep their existing single-leader topology - only the stateless API
tier flips.

```powershell
kubectl apply -f deploy/k8s/blue-green/
.\scripts\blue_green_switch.ps1 -Image ghcr.io/org/SentinelSOC:1.2.3
```

The switch script (1) deploys into the idle release, (2) waits for rollout
status + pod availability, (3) flips the Service selector atomically, and
(4) scales the previous release to zero. Any failure aborts before traffic
moves; re-running the script flips back (rollback). Zero-downtime rolling
updates remain available on the classic manifest
(`deploy/k8s/baraq.yaml`) when you prefer them.

