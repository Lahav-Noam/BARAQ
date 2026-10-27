# BARAQ SOC Platform — Development Roadmap

**Author:** natahan  
**Date:** 2026-09-07 (updated 2026-09-27)  
**Status:** Completed — see "Remaining production work" below for what is *not* done

## Remaining production work (as of 2026-09-27)

The items below were identified by running the system end to end and are **not**
complete. They are tracked in [`CHANGELOG.md`](CHANGELOG.md) under "Known
issues".

1. **External penetration test** — not performed; needs an outside party.
2. **Typecheck gate** — pyright is installed and configured
   (`pyrightconfig.json`) but 170 findings remain (SQLAlchemy `Optional`
   patterns, argument types; zero undefined variables). Not wired into CI.
3. **ML unsupervised recall** — 0.286 on the hold-out split (2/7), down from
   ~0.36. The rule/hybrid layers carry detection (hybrid recall 0.939).
   Restoring this touches `backend/ml/anomaly.py`, which has concurrent work in
   flight.
4. **Compliance assessments are in-memory only** — they reset to `unassessed`
   on restart, so they cannot be used as audit evidence yet.
5. **Entity graph is not natively multi-tenant** — `entity_nodes` has no `org`
   column; isolation is enforced at the API layer (entities must appear in the
   caller's own telemetry). True multi-tenancy needs `entity_nodes.org` plus a
   backfill migration.
6. **Fifteen API surfaces have no tenant column** — the v2 alerts and incidents
   APIs plus risk, UEBA, investigation, intel, compliance, telemetry, evaluation
   and others are reachable by any authenticated analyst. Acceptable while the
   deployment is single-tenant; not acceptable if a second organization is ever
   onboarded. Restricting them to admin was implemented and reverted because it
   blanks eight analyst-facing screens. Full analysis and the three resolution
   options: [`docs/SINGLE_TENANT.md`](docs/SINGLE_TENANT.md). Specified by
   `tests/test_single_tenant.py` (14 expected failures).
7. **Scale not load-tested** — verified on one endpoint only; 50–200 machines
   and the resulting event volume are unproven.
8. **Detection tuning** — two rule false positives were found and fixed against
   real traffic (C2 beaconing 104 → 0; masquerading on an empty process path;
   port-scan counting a host talking to itself). The C2 rewrite initially also
   silenced a *true* positive (a 24 MB PowerShell exfiltration), which the
   hold-out suite caught; interpreters and LOLBins now have their own lower
   volume bar. Expect more from a week of real traffic; the systematic fix is
   to run it and work the noise list.
9. **Response actions not rehearsed on a real host** — validation and injection
   defences are unit-tested and command polling works over TLS, but no live
   containment has been executed. Destructive SOAR ships disabled by design.
10. **Full-suite run is the last gate** — see `CHANGELOG.md` for the current
   numbers.

---

## High-Level Network ML Detector (Candidate Track)

**Status**: In progress — see [`docs/ml-high-level-todo.md`](docs/ml-high-level-todo.md) for detailed TODO, evidence log, and definition of done.

**Key deliverables**:
- [`backend/ml/high_level.py`](backend/ml/high_level.py) — 92-feature causal detector (IF + rule fusion)
- [`scripts/bench_high_level.py`](scripts/bench_high_level.py) — S2/S3/S4 benchmark runner
- [`scripts/simulate_attack.py`](scripts/simulate_attack.py) — Live-like attack simulation
- [`validation/external/README.md`](validation/external/README.md) — External validation package
- [`docs/model-card-high-level.md`](docs/model-card-high-level.md) — Model card
- [`tests/ml/test_high_level.py`](tests/ml/test_high_level.py) — Unit tests (18 passing)

**Current results**: 98-100% recall on BOTSv1 Campaigns A/B at 0.52% local FPR (S2/S3/S4). Ablation shows rules critical for Campaign A (AUC drops 7.3% without them). Live-like simulation reveals domain-shift limitations.

---

## Table of Contents

1. [Deployment Blockers](#1-deployment-blockers)
2. [Test Coverage Expansion](#2-test-coverage-expansion)
3. [Security Hardening](#3-security-hardening)
4. [Feature Completion](#4-feature-completion)
5. [CI/CD Pipeline](#5-cicd-pipeline)
6. [Documentation](#6-documentation)
7. [UI/UX Improvements](#7-uiux-improvements)

---

## 1. Deployment Blockers

### 1.1 PostgreSQL Service Won't Start

**Issue:** The Windows service "Baraq" fails to start via `Start-Service`.

**Root Cause:** The service binary path or configuration is broken.

**Fix:**
```powershell
# Check service configuration
sc.exe qc Baraq

# Re-register the service
sc.exe delete Baraq
sc.exe create Baraq binPath= "F:\My Project\Baraq\pg\pgsql\bin\pg_ctl.exe start -D F:\My Project\Baraq\pg\data2" start= auto

# Or use the working data directory
pg_ctl start -D "F:\My Project\Baraq\pg\data2" -l "F:\My Project\Baraq\pg\pg_service.log"
```

**Priority:** CRITICAL — Nothing works without the database.

### 1.2 Docker Desktop Not Running

**Issue:** `docker ps` fails with "cannot find the path specified."

**Fix:**
1. Start Docker Desktop manually
2. Or use `colima` / `nerdctl` as lightweight alternatives
3. Or run PostgreSQL natively (current approach)

**Priority:** HIGH — Blocks containerized deployment.

### 1.3 Backend Startup Race Condition

**Issue:** Backend starts before PostgreSQL is ready, causing `ConnectionTimeout`.

**Fix:** Add retry logic to database connection:
```python
# backend/database/connection.py
import time
from sqlalchemy import create_engine

MAX_RETRIES = 10
RETRY_DELAY = 2

for attempt in range(MAX_RETRIES):
    try:
        engine = create_engine(DATABASE_URL)
        engine.connect()
        break
    except OperationalError:
        if attempt == MAX_RETRIES - 1:
            raise
        time.sleep(RETRY_DELAY)
```

**Priority:** HIGH — Causes intermittent startup failures.

---

## 2. Test Coverage Expansion

### 2.1 Current State

| Category | Tests | Coverage |
|----------|-------|----------|
| Backend (pytest) | 120+ files | API endpoints, auth, ML, detection |
| Frontend (Playwright) | 17 tests | Login, registration, validation |
| E2E (manual) | 1 file | All API endpoints (skipped by default) |

### 2.2 Playwright Tests to Add

#### Priority 1: Core Pages
| Page | Test Cases |
|------|------------|
| Dashboard | Load, summary cards, charts render, time range filter |
| Alerts | List loads, filter by severity, filter by status, pagination |
| Alert Detail | Load by ID, notes add, status change, action buttons |
| Incidents | List loads, create incident, link alerts |

#### Priority 2: Management Pages
| Page | Test Cases |
|------|------------|
| Users | List users, create user, approve user, delete user |
| Settings | Load settings, save changes, API key display |
| Endpoints | List agents, send command, command history |
| Detection Rules | List rules, enable/disable, edit rule |

#### Priority 3: Advanced Features
| Page | Test Cases |
|------|------------|
| Investigation | Alert investigation, process tree, timeline |
| Threat Intel | Lookup indicator, mark malicious, feed status |
| SOAR/Automation | Create playbook, run playbook, approval flow |
| Reports | Generate report, download PDF, schedule report |

### 2.3 Backend Tests to Add

| Area | Missing Tests |
|------|---------------|
| Auth | MFA setup/confirm/disable, password change, rename account |
| Alerts | Alert grouping, suppression rules, verdict submission |
| ML | Online learning, drift detection, ensemble status |
| SOAR | Playbook CRUD, run history, preview mode |
| Search | Full-text search, suggest, saved searches |

### 2.4 Test Infrastructure

**Add to `frontend/package.json`:**
```json
{
  "scripts": {
    "test:e2e:dashboard": "playwright test e2e/dashboard.spec.js",
    "test:e2e:alerts": "playwright test e2e/alerts.spec.js",
    "test:e2e:all": "playwright test",
    "test:e2e:report": "playwright show-report"
  }
}
```

---

## 3. Security Hardening

### 3.1 Environment Variables

**Current Issue:** `.env` contains plaintext database password:
```
BARAQ_DATABASE_URL=postgresql+psycopg://postgres:password@127.0.0.1:55432/baraq
```

**Fix:** Move to DPAPI vault:
```python
# Remove from .env, store in vault
from backend.vault import get_vault
vault = get_vault()
vault.set("BARAQ_DATABASE_URL", "postgresql+psycopg://postgres:password@127.0.0.1:55432/baraq")
```

**Priority:** CRITICAL — Plaintext credentials in version control.

### 3.2 Dev Keys Warning

**Current Issue:** Logs show `BARAQ_ALLOW_DEV_KEYS=1`.

**Fix:**
```bash
# In .env
BARAQ_ALLOW_DEV_KEYS=0
BARAQ_API_KEYS={"admin":"<strong-random-key>"}
```

**Priority:** HIGH — Dev keys in production.

### 3.3 Secrets Rotation

**Add:** Automated password/keys rotation:
```python
# backend/security/rotation.py
def rotate_admin_password():
    new_password = secrets.token_urlsafe(24)
    vault.set("BARAQ_ADMIN_PASSWORD", new_password)
    logger.info("Admin password rotated")
```

### 3.4 Audit Logging

**Current:** Auth audit exists but no SIEM export.

**Add:** Export audit logs to external SIEM:
```python
@app.post("/api/auth/audit/export")
def export_audit(format: str = "json"):
    # Export to Splunk/ELK/Sentinel
    pass
```

---

## 4. Feature Completion

### 4.1 Alert Correlation Rules

**Current:** 12 correlation rules loaded but no UI to manage them.

**Build:**
- `/correlation-rules` page — list, enable/disable, edit YAML
- Rule testing — simulate events, see which rules fire
- Rule templates — pre-built MITRE ATT&CK chains

### 4.2 SOAR Playbooks

**Current:** API exists, UI exists but untested.

**Build:**
- Playbook visual editor (drag-and-drop)
- Playbook versioning
- Execution history with replay
- Integration connectors (CrowdStrike, Sentinel, etc.)

### 4.3 UEBA/Insider Threat

**Current:** Pages exist (`/ueba`, `/insider-threat`) but need validation.

**Build:**
- User risk scoring timeline
- Anomaly detection visualization
- Peer group comparison
- Data exfiltration alerts

### 4.4 Fleet Management

**Current:** `/fleet-config` page exists.

**Build:**
- Agent deployment wizard
- Configuration profiles
- Bulk agent updates
- Health monitoring dashboard

---

## 5. CI/CD Pipeline

### 5.1 GitHub Actions Workflow

**Create `.github/workflows/ci.yml`:**
```yaml
name: BARAQ CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_DB: baraq_test
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: test
        ports:
          - 5432:5432
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -r requirements.txt -r requirements-dev.txt
      - run: pytest tests/ -v --tb=short
        env:
          BARAQ_DATABASE_URL: postgresql+psycopg://postgres:test@localhost:5432/baraq_test

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: cd frontend && npm ci
      - run: cd frontend && npx playwright install chromium
      - run: cd frontend && npx playwright test
        env:
          BASE_URL: http://localhost:5173

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install ruff mypy
      - run: ruff check backend/
      - run: mypy backend/ --ignore-missing-imports
```

### 5.2 Pre-commit Hooks

**Create `.pre-commit-config.yaml`:**
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.5.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        args: [--ignore-missing-imports]
```

### 5.3 Deployment Pipeline

**Add to CI:**
```yaml
  deploy:
    needs: [backend-tests, frontend-tests, lint]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Docker image
        run: docker build -t baraq/soc:${{ github.sha }} .
      - name: Push to registry
        run: docker push baraq/soc:${{ github.sha }}
      - name: Deploy to production
        run: |
          kubectl set image deployment/baraq-api baraq-api=baraq/soc:${{ github.sha }}
```

---

## 6. Documentation

### 6.1 API Documentation

**Add OpenAPI/Swagger:**
```python
# backend/main.py
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="BARAQ SOC API",
        version="1.4.0",
        description="Security Operations Center API",
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
```

### 6.2 Architecture Documentation

**Create `docs/architecture.md`:**
- System overview
- Component diagram
- Data flow
- Database schema
- API endpoints

### 6.3 Deployment Guide

**Create `docs/deployment.md`:**
- Prerequisites
- Docker deployment
- Native deployment
- Kubernetes deployment
- Environment variables reference

### 6.4 User Guide

**Create `docs/user-guide.md`:**
- Getting started
- Dashboard overview
- Alert management
- Incident response
- Report generation

---

## 7. UI/UX Improvements

### 7.1 Mobile Responsive

**Current Issue:** Sidebar Layout doesn't work on mobile.

**Fix:**
```jsx
// frontend/src/components/layout/Layout.jsx
const [sidebarOpen, setSidebarOpen] = useState(false);

return (
  <div className="flex h-screen">
    {/* Mobile overlay */}
    {sidebarOpen && (
      <div className="fixed inset-0 bg-black/50 z-40 lg:hidden"
           onClick={() => setSidebarOpen(false)} />
    )}
    
    {/* Sidebar */}
    <aside className={`
      fixed lg:static inset-y-0 left-0 z-50
      w-64 transform transition-transform
      ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
    `}>
      <Sidebar />
    </aside>
    
    {/* Main content */}
    <main className="flex-1 overflow-auto">
      <Topbar onMenuClick={() => setSidebarOpen(true)} />
      <Outlet />
    </main>
  </div>
);
```

### 7.2 Dark/Light Theme Toggle

**Current:** Theme context exists but no toggle button.

**Build:**
```jsx
// frontend/src/components/ui/ThemeToggle.jsx
export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button onClick={toggle} className="p-2 rounded-lg">
      {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
    </button>
  );
}
```

### 7.3 Keyboard Shortcuts

**Add command palette (Cmd+K):**
- Already exists: `CommandPalette.jsx`
- **Need:** Wire up shortcuts for common actions
  - `Cmd+K` — Command palette
  - `Cmd+Shift+A` — New alert
  - `Cmd+Shift+I` — New incident
  - `Cmd+/` — Search

### 7.4 Real-time Notifications

**Current:** WebSocket exists but not connected to UI.

**Build:**
```jsx
// frontend/src/hooks/useNotifications.js
export function useNotifications() {
  useEffect(() => {
    const ws = new WebSocket('/ws/notifications');
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      toast[data.type](data.message);
    };
    return () => ws.close();
  }, []);
}
```

---

## Priority Matrix

| Priority | Task | Effort | Impact |
|----------|------|--------|--------|
| P0 | Fix PostgreSQL service | 2h | Critical |
| P0 | Fix .env plaintext credentials | 1h | Critical |
| P1 | CI/CD pipeline | 4h | High |
| P1 | Mobile responsive layout | 3h | High |
| P2 | Dashboard Playwright tests | 4h | Medium |
| P2 | Alerts Playwright tests | 4h | Medium |
| P2 | API documentation (OpenAPI) | 2h | Medium |
| P3 | SOAR playbook editor | 2w | High |
| P3 | UEBA validation | 1w | Medium |
| P3 | Keyboard shortcuts | 1d | Low |

---

## Next Steps

1. [x] Fix PostgreSQL service startup
2. [x] Move secrets to DPAPI vault
3. [x] Create GitHub Actions CI workflow
4. [x] Add Dashboard page Playwright tests
5. [x] Add Alerts page Playwright tests
6. [x] Generate OpenAPI documentation
7. [x] Fix mobile responsive layout
8. [x] Add real-time notifications

---

**Last Updated:** 2026-09-08  
**Author:** natahan  
**Contact:** natahanjr@gmail.com
