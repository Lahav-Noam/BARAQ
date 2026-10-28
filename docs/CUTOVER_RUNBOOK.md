# BARAQ production cutover runbook

**Owner:** you (approver). **Operator:** this session.
**Target:** replace the current SOC with BARAQ in a single change window, using batched
agent rollout inside that window so there is never a total detection blind spot.

Status of every gate below is marked `[x] verified` only if it was actually executed and
observed. Nothing here is assumed.

---

## 0. Verified already (do not redo)

| Gate | Result |
|---|---|
| Backend test suite | 2008 passed, 8 skipped, 1 order-dependent failure since fixed |
| Frontend build + tests | build OK, 37/37 vitest |
| Critical lint / compile | `ruff E9,F821,F601` clean, compileall clean |
| PowerShell scripts | all parse clean (agent, agent.ps1, install_agent, updater, gen_cert) |
| Docker image build | `baraq/soc:hardening-check`, 1.83 GB |
| Container boot (production profile) | healthy, `/api/health` 200 |
| Production config gate | refuses dev keys, unparseable keys, localhost CORS, missing threat intel, no TLS, destructive SOAR, weak admin password |
| Auth in container | login 200, session + CSRF cookies issued, `/api/auth/me` 200, all API panels 200 |
| Key rejection | wrong `X-API-Key` → 401 |
| Unauthenticated surface | `/api/system/status` 401, `/metrics` 401, report files not served statically |
| **Agent install → verified telemetry** | installer prints "Installed and VERIFIED" only after the server accepts records |
| **Agent on a real endpoint** | `laptop-canary-001` reporting, 11k+ events, 26 alerts raised |
| **Agent auto-start** | scheduled task registers with a qualified principal and survives reboot |
| **TLS transport** | server serves real HTTPS; agent pins the certificate thumbprint; 435 records accepted over TLS |
| **Backup + restore** | 41.6 MB dump restored to a scratch DB with exact row parity (11,122 events / 26 alerts / 80 audit rows) |

### Agent install command (verified)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_agent.ps1 `
  -Server https://<host>:8443 -Key <agent-secret> -Org <dept> `
  -Interval 15 -TlsCert <path>\baraq.crt
```

- Defaults to the **self-contained PowerShell agent** (no Python, no pywin32 needed).
  Add `-AgentType python` only on hosts that also have the `backend` package deployed.
- The installer verifies telemetry before reporting success. If it cannot, it prints
  `TELEMETRY NOT VERIFIED` - treat that as a failed install, not a warning.
- Server-side, `BARAQ_AGENT_KEYS` is `{"<agent-secret>": "<agent-id>"}` - the **secret is
  the JSON key**, the agent id is the value. Reversed maps authenticate nothing (401).

## 1. Open items that need you

These are **not** optional. Each one leaves a real risk if skipped.

1. **External penetration test.** Not done. A SOC that holds credentials, executes
   response actions and is reachable from 200 endpoints is exactly the kind of target
   that gets tested adversarially. Budget a few days.
2. **Real TLS certificate.** The transport works and pinning is verified, but the current
   cert is a self-signed one from `scripts/gen_cert.ps1` covering the local SANs. For
   production use a company CA cert and re-run `gen_cert.ps1`/issue against the real host
   name, then pass `-TlsCert` (or `-TlsCertSha256`) to the installer.
3. **Backups — restore verified, schedule not yet set.** The restore drill passed with
   exact row parity. Still required: a scheduled task (see `scripts/install_backup_task.ps1`)
   plus a copy off the host, and confirmation the schedule actually runs unattended
   (it now locates `pg_dump` itself).
4. **Typecheck.** `pyright` is not installed; the project has no static type gate. Add it
   to `requirements-dev.txt` in CI or accept the risk knowingly.
5. **ML detection quality.** The unsupervised layer catches 2/7 unseen attacks on the
   holdout split. Detection today rides on the rule layer (hybrid recall 0.939). The
   loaded v121 bundle has no campaign-held-out validation, so it is **shadow/advisory
   only**; do not enable autonomous blocking. The deployment contract, promotion gate,
   monitoring endpoint, and rollback procedure are in
   [`docs/ml-deployment-readiness.md`](ml-deployment-readiness.md).
6. **Remote response actions untested on real hardware.** Command *validation* and
   injection defences are unit-tested, and command polling now works over TLS, but no
   live `kill_process` / `quarantine` / `block_ip` has been executed against a real
   endpoint. Destructive SOAR ships disabled on purpose — keep it that way until someone
   has rehearsed a containment on a disposable machine.

## 2. Prerequisites on the BARAQ host

- [ ] Docker Desktop / Engine running, ≥8 GB RAM, ≥40 GB free disk
- [ ] Host firewall: only the admin LAN may reach 8001; 5432/6379 stay internal
- [ ] Hostname resolvable by the console origin, and `BARAQ_CORS_ORIGINS` set to the real
      origin (production refuses localhost)
- [ ] NTP/time sync healthy — token freshness and MFA depend on it
- [ ] Decide the org/tenant model: single company (org `""`) or per-department orgs.
      This changes the entity graph isolation story (see §6)

## 3. Generate production secrets (with you watching)

Never on a shared terminal, never pasted into chat.

```
cd F:\My Project\Baraq
venv\Scripts\python.exe scripts\rotate_secrets.py --generate-only
```

Review the output yourself. Required non-default values:

| Variable | Rule |
|---|---|
| `BARAQ_API_KEYS` | `{"<32+ char random>":"admin"}` — no `baraq-dev-*` |
| `BARAQ_AGENT_KEYS` | one key per rollout batch, never reused across tenants |
| `BARAQ_TOKEN_SECRET` | ≥32 random bytes, unique per deployment |
| `BARAQ_ADMIN_PASSWORD` | unique, ≥16 chars |
| `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `GRAFANA_ADMIN_PASSWORD` | unique each |
| `BARAQ_CORS_ORIGINS` | the real console origin(s) |

Store them in the host's secret store or a DPAPI vault, not in a shared `.env` and not in
git. `BARAQ_SKIP_SECRET_GEN=0` so the first boot writes `secrets.dat` under the service
account.

## 4. The change window

### Gate 0 — server up, nothing else touched
1. `docker compose up -d db redis` → wait for both healthy.
2. Start the API with the generated secrets + TLS cert.
3. `curl https://<host>:8001/api/health` → `status: ok` or `warning` **only** for
   "ML model not trained yet".
4. Log in with the new admin password. Confirm the dashboard loads and shows zero alerts.
5. **Go/no-go:** if health is not ok, stop. The old SOC is still running.

### Gate 1 — canary agents (3 machines)
Install on 3 representative endpoints (one server, one workstation, one laptop) using the
installer with the pinned certificate hash:

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_agent.ps1 `
  -ServerUrl https://<host>:8001 -ApiKey <agent-key> -TlsCertSha256 <sha256>
```

Verify, per machine, before touching anything else:
- [ ] agent heartbeat in `/api/endpoints` shows `healthy`
- [ ] events arriving from that host in `/api/events` (count is climbing)
- [ ] `/api/alerts` populating if the host generates any test event
- [ ] agent logs show no TLS or key errors
- [ ] `scripts\agent_updater.ps1` runs clean on one machine (hash + rollback path)

**Go/no-go:** all three verified. If not, fix or roll the canary back — do not proceed.

### Gate 2 — fleet in batches
Roll out in batches (10–25 machines), verifying after each batch:
- [ ] endpoint health count matches the batch
- [ ] event rate scales roughly linearly
- [ ] no duplicate/phantom hosts
- [ ] dashboard and reports still responsive

Keep the old SOC running through this phase. Its alerting is your comparison baseline.

### Gate 3 — decommission the old SOC
Only after the fleet has been healthy for a minimum observation period (recommend ≥72h,
not minutes):
- [ ] BARAQ detections compared against the old SOC's for that period
- [ ] no coverage gaps found in rules that matter to you
- [ ] old SOC put into a documented, reversible standby state — **not deleted**
- [ ] rollback path written down and rehearsed:
      redeploy agents with the previous config, re-enable the old collector

## 5. Rollback triggers

Roll back immediately if any of these occur:
- agents stop reporting or event rate collapses
- detection gap on a technique you actively hunt
- auth/login failures for real analysts
- certificate expiry or key rotation failure
- database corruption or restore failure

Rollback = stop the rollout, point agents back at the old collector, keep BARAQ running
for forensics. Do not delete BARAQ data; the incident history is the evidence.

## 6. Known limitations to accept or fix later

- **Entity graph is a single global namespace.** `entity_nodes` is unique on
  `(kind, name)` with no `org` column, so graph visibility is enforced at the API layer
  (entities must appear in the caller's own telemetry). For a single-company deployment
  this is fine. For true multi-tenancy, `entity_nodes.org` plus a backfill migration is
  required.
- **Compliance assessments are in-memory only.** They reset to `unassessed` on restart.
  Do not use them as audit evidence yet.
- **No external pentest, no typecheck gate** (see §1).
- **ML unsupervised recall** is 0.286 on holdout; rule layer carries detection.
