"""Central configuration for BARAQ.

All tunable parameters of the platform live here so the application can be
adjusted without touching business logic. Optimised for a low-resource
single Windows 11 laptop (i5 / 12 GB RAM).
"""

import getpass
import json
import logging
import os
import secrets as _secrets
import socket
import sys
from pathlib import Path

logger = logging.getLogger("baraq.config")

# --------------------------------------------------------------------------
# Frozen (PyInstaller) layout
# --------------------------------------------------------------------------
#: True when running from a packaged executable.
FROZEN = getattr(sys, "frozen", False)
if FROZEN:
    #: Read-only bundled resources live in the PyInstaller bundle (_MEIPASS).
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    #: Writable runtime data (database, logs, reports, .env) lives next to the exe.
    APP_DIR = Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR = Path(__file__).resolve().parent
    APP_DIR = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# .env loader (no third-party dependency)
# --------------------------------------------------------------------------
def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from a .env file into os.environ (non-overriding)."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(APP_DIR / ".env")

# --------------------------------------------------------------------------
# Runtime profile
# --------------------------------------------------------------------------
#: "development" (default - dev conveniences allowed), "production" (secure
#: gate below refuses insecure defaults) or "test" (test-suite).
BARAQ_ENV = os.environ.get("BARAQ_ENV", "development").strip().lower()
IS_PRODUCTION = BARAQ_ENV == "production"


# --------------------------------------------------------------------------
# First-run secure setup
# --------------------------------------------------------------------------
#: The project .env file (next to this file's parent, i.e. project root).
ENV_PATH = APP_DIR / ".env"

#: Generated randomly per install - never hardcoded. Fresh installs seed the
#: admin with this and mark the account (must_change_password) so the console
#: forces the operator to replace it before use.
DEFAULT_ADMIN_PASSWORD = _secrets.token_urlsafe(16)

#: Retired well-known bootstrap password. Release builds before 1.0.9 bundled
#: this value into a shared ``dist/.env`` seed; it is detected and rotated on
#: startup so an upgraded install cannot keep a credential that every other
#: copy of the same build also knows. This is a public legacy default, not a
#: live secret.
INSECURE_BOOTSTRAP_PASSWORD = "baraqadmin"  # ggignore

#: One-time credential handoff for windowed/packaged installs, written next to
#: the executable when random credentials are generated. Deleted as soon as
#: the admin changes the password (see ``clear_first_run_credentials``).
FIRST_RUN_CREDENTIALS_PATH = APP_DIR / "first_run_credentials.txt"

#: These are *names* of environment variables, kept in one place so the
#: marker check below and the persisted .env block always stay in sync.
_first_run_vars = (
    "BARAQ_ADMIN_PASSWORD",
    "BARAQ_API_KEYS",
    "BARAQ_TOKEN_SECRET",
)

#: Additional credential values that may live in .env and should also be
#: migrated into the DPAPI vault (agent keys, AI API key).
_credential_vars = _first_run_vars + ("BARAQ_AGENT_KEYS", "BARAQ_AI_API_KEY")

#: Pre-rename environment/vault prefix, used so credentials written before
#: the BARAQ rename keep working and are adopted under the new names.
_LEGACY_PREFIX = "SENTINEL_"


def _legacy_name(name: str) -> str:
    """Map a BARAQ_* secret name back to its pre-rename SENTINEL_* form."""
    return _LEGACY_PREFIX + name[len("BARAQ_") :] if name.startswith("BARAQ_") else name


def _get_vault():
    """Return the DPAPI secret vault (cached; degrades gracefully off-Windows)."""
    from backend.vault import SecretVault

    return SecretVault(APP_DIR / "secrets.dat")


# Priorities: vault (DPAPI) > environment > .env. The vault is preferred for
# secrets so they never need to live in plaintext on disk.
def _secret(name: str, default: str = "") -> str:
    """Return a secret preferring the DPAPI vault, then the environment."""
    legacy = _legacy_name(name)
    for key in (name, legacy):
        value = os.environ.get(key)
        if value:
            return value
        try:
            value = _get_vault().get(key)
        except Exception:
            value = None
        if value:
            return value
    return default


def _migrate_env_secrets_to_vault(vault, env_path: Path) -> None:
    """Move plaintext secrets found in .env into the DPAPI vault.

    Once a value is safely stored in the vault, its plaintext line is removed
    from .env so credentials never linger on disk in cleartext. The current
    process keeps working because values are already in os.environ.
    """
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    secrets = {}
    kept = []
    changed = False
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.partition("=")[0].strip()
            if key in _credential_vars:
                value = stripped.partition("=")[2].strip().strip('"').strip("'")
                if value:
                    secrets[key] = value
                changed = True
                continue
        kept.append(line)
    if not secrets:
        return
    try:
        vault.set_many(secrets)
    except Exception:
        return
    if changed:
        try:
            env_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        except OSError:
            pass


def _strip_env_first_run_vars(env_path: Path) -> None:
    """Remove bootstrap credential lines from .env before regenerating them.

    ``_load_dotenv`` is non-overriding, so leaving an old bootstrap line in
    place would make the next process start regenerate credentials again.
    """
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    kept = [
        line
        for line in lines
        if not (
            line.strip()
            and not line.lstrip().startswith("#")
            and "=" in line
            and line.partition("=")[0].strip() in _first_run_vars
        )
    ]
    if len(kept) == len(lines):
        return
    try:
        env_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    except OSError:
        pass


def _write_first_run_credentials(values: dict[str, str]) -> bool:
    """Write the one-time bootstrap credentials next to the executable.

    The encrypted vault is the durable store; this file exists only so a
    windowed packaged build (no console) can surface the initial password to
    the operator. It is removed after the first successful password change.
    """
    lines = [
        "BARAQ first-run credentials",
        "=" * 32,
        "",
        "Log in and change the admin password immediately.",
        "This file is deleted automatically after the password change.",
        "",
        f"Username: {os.environ.get('BARAQ_ADMIN_USERNAME', 'admin')}",
        f"Password: {values.get('BARAQ_ADMIN_PASSWORD', '')}",
        "",
    ]
    try:
        api_keys = json.loads(values.get("BARAQ_API_KEYS", "{}"))
    except (TypeError, ValueError):
        api_keys = {}
    for key, role in api_keys.items():
        lines.append(f"{str(role).title()} API key: {key}")
    try:
        path = FIRST_RUN_CREDENTIALS_PATH
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        if os.name == "nt":
            try:
                import subprocess

                subprocess.run(
                    [
                        "icacls",
                        str(path),
                        "/inheritance:r",
                        "/grant:r",
                        f"{getpass.getuser()}:F",
                    ],
                    check=False,
                    capture_output=True,
                    timeout=10,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        return True
    except OSError:
        return False


def clear_first_run_credentials() -> None:
    """Delete the one-time credential handoff file (best effort)."""
    try:
        FIRST_RUN_CREDENTIALS_PATH.unlink()
    except OSError:
        pass


def _ensure_secure_secrets(env_path: Path = ENV_PATH) -> None:
    """Generate random admin credentials on first run and persist them.

    Sensitive credentials are stored DPAPI-encrypted in ``secrets.dat``
    (Windows) so they never sit in plaintext on disk'. When DPAPI is not
    available (non-Windows / CI), they are written to .env instead.

    Runs once at import time. Skipped when credentials are already configured
    (operator-provided via environment/.env, or generated on a previous run),
    or when ``BARAQ_SKIP_SECRET_GEN=1`` (used by the test suite so tests
    never touch the real .env file). The credentials are printed exactly once
    so the operator can save them.
    """
    if os.environ.get("BARAQ_SKIP_SECRET_GEN", "").lower() in ("1", "true", "yes"):
        return

    vault = _get_vault()

    # One-time migration: credentials stored under the pre-rename SENTINEL_*
    # names (vault or .env) are adopted under their new BARAQ_* names so the
    # existing admin password / API keys keep working without regeneration.
    _adopted = {}
    for _name in _first_run_vars:
        if _name.startswith("BARAQ_") and not (
            vault.get(_name) or os.environ.get(_name)
        ):
            _old = _legacy_name(_name)
            _value = os.environ.get(_old) or vault.get(_old)
            if _value:
                _adopted[_name] = _value
    if _adopted:
        try:
            vault.set_many(_adopted)
        except Exception:
            pass
        for _k, _v in _adopted.items():
            os.environ.setdefault(_k, _v)

    # Existing configuration may already be in the vault (preferred) or .env.
    configured = {
        name: vault.get(name) or os.environ.get(name) for name in _first_run_vars
    }
    # A shared bootstrap password from a pre-1.0.9 release build is treated as
    # unconfigured: rotate all three values instead of keeping a credential
    # every copy of that build knows.
    insecure_bootstrap = (
        configured.get("BARAQ_ADMIN_PASSWORD") == INSECURE_BOOTSTRAP_PASSWORD
    )
    if all(configured.values()) and not insecure_bootstrap:
        _migrate_env_secrets_to_vault(vault, env_path)
        return

    if not insecure_bootstrap:
        # Migration: secrets exist in plaintext .env but not yet in the vault.
        _migrate_env_secrets_to_vault(vault, env_path)
        if all(vault.get(name) or os.environ.get(name) for name in _first_run_vars):
            return

        try:
            existing = env_path.read_text(encoding="utf-8")
        except OSError:
            existing = ""
        if all(name + "=" in existing for name in _first_run_vars):
            return

    admin_password = DEFAULT_ADMIN_PASSWORD
    admin_key = "baraq-admin-" + _secrets.token_urlsafe(10)
    analyst_key = "baraq-analyst-" + _secrets.token_urlsafe(10)
    api_keys_json = json.dumps({admin_key: "admin", analyst_key: "analyst"})
    token_secret = _secrets.token_hex(32)
    new_values = {
        "BARAQ_ADMIN_PASSWORD": admin_password,
        "BARAQ_API_KEYS": api_keys_json,
        "BARAQ_TOKEN_SECRET": token_secret,
    }

    # Remove old bootstrap lines before persisting replacements: _load_dotenv
    # is non-overriding, so a stale bootstrap line would otherwise be
    # re-read on the next start and trigger another rotation.
    _strip_env_first_run_vars(env_path)

    # Prefer the DPAPI vault; fall back to plaintext .env only when needed.
    stored_in_vault = False
    try:
        vault.set_many(new_values)
        stored_in_vault = True
    except Exception:
        try:
            block = (
                "\n# ------------------------------------------------------------------\n"
                "# BARAQ first-run generated credentials (keep private)\n"
                "# ------------------------------------------------------------------\n"
                + "".join(f"{k}={v}\n" for k, v in new_values.items())
            )
            with open(env_path, "a", encoding="utf-8") as fh:
                fh.write(block)
        except OSError:
            pass  # session-only credentials below still work for this run

    # Make the current process pick the generated values up immediately.
    for k, v in new_values.items():
        os.environ[k] = v

    credentials_file = _write_first_run_credentials(new_values)
    if insecure_bootstrap:
        logger.warning(
            "Rotated the retired shared bootstrap credentials (admin password, "
            "API keys and token secret): BARAQ_ADMIN_PASSWORD was the "
            "well-known retired bootstrap value."
        )

    username = os.environ.get("BARAQ_ADMIN_USERNAME", "admin")
    print("=" * 62)
    print("BARAQ first-run setup complete")
    print("=" * 62)
    print("Random credentials were generated ")
    if stored_in_vault:
        print("and stored encrypted in secrets.dat")
        print(f"  ({ENV_PATH.parent / 'secrets.dat'})")
    else:
        print(f"and saved to: {env_path}")
    print()
    # Show partial password to avoid full credential in logs/CI output
    masked = admin_password[:3] + "***" + admin_password[-2:] if len(admin_password) > 5 else "***"
    print(f"  Dashboard login : {username} / {masked}")
    if credentials_file:
        print(f"  Full credentials: {FIRST_RUN_CREDENTIALS_PATH}")
        print("  (delete after changing the password; removed automatically)")
    else:
        print(f"  Full password   : {admin_password}")
        print("  (first_run_credentials.txt could not be written - save it now)")
    print(f"  Admin API key   : {admin_key[:10]}...")
    print(f"  Analyst API key : {analyst_key[:12]}...")
    print()
    print("Save them now - they will not be shown again.")
    print("=" * 62)


_ensure_secure_secrets()

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
PROJECT_ROOT = APP_DIR
BACKEND_DIR = BUNDLE_DIR
DATABASE_DIR = APP_DIR / "database"
LOG_DIR = APP_DIR / "logs"
REPORT_DIR = APP_DIR / "reports"
DOCUMENTATION_DIR = APP_DIR / "documentation"
DATASET_DIR = APP_DIR / "datasets"

for _d in (DATABASE_DIR, LOG_DIR, REPORT_DIR, DATASET_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------
# OTRF Security-Datasets import
# --------------------------------------------------------------------------
#: Directory containing OTRF Security-Datasets for ML training.
#: Defaults to APP_DIR/datasets/otrf. Set BARAQ_OTRF_DATA_DIR to override.
OTRF_DATA_DIR = Path(
    os.environ.get(
        "BARAQ_OTRF_DATA_DIR",
        str(DATASET_DIR / "otrf"),
    )
)
OTRF_DATA_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------
# Research dataset collector
# --------------------------------------------------------------------------
#: Defaults for a new dataset collection session (overridable per session
#: through the API; see backend/dataset/).
DATASET_NAME = os.environ.get("BARAQ_DATASET_NAME", "BARAQ_Research_Dataset")
DATASET_TARGET_EVENTS = int(os.environ.get("BARAQ_DATASET_TARGET_EVENTS", "1000000"))
DATASET_EVENTS_PER_FILE = int(os.environ.get("BARAQ_DATASET_EVENTS_PER_FILE", "100000"))
DATASET_EXPORT_INTERVAL_HOURS = int(
    os.environ.get("BARAQ_DATASET_EXPORT_INTERVAL_HOURS", "24")
)
DATASET_FORMAT = os.environ.get("BARAQ_DATASET_FORMAT", "csv")
DATASET_ENABLED = os.environ.get("BARAQ_DATASET_ENABLED", "false").lower() in (
    "1",
    "true",
    "yes",
)
DATASET_ANONYMIZE = os.environ.get("BARAQ_DATASET_ANONYMIZE", "true").lower() in (
    "1",
    "true",
    "yes",
)
DATASET_INCLUDE_LABELS = os.environ.get(
    "BARAQ_DATASET_INCLUDE_LABELS", "false"
).lower() in (
    "1",
    "true",
    "yes",
)
#: Events consumed per sweep cycle (rate-limit so normal telemetry is not
#: impacted by the research store).
DATASET_COLLECT_BATCH = int(os.environ.get("BARAQ_DATASET_COLLECT_BATCH", "500"))
#: Rows read per keyset batch while streaming an export.
DATASET_EXPORT_BATCH = int(os.environ.get("BARAQ_DATASET_EXPORT_BATCH", "10000"))
DATASET_SCHEMA_VERSION = "v1"
DATASET_COLLECTOR_VERSION = "v1"

# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
DATABASE_URL = _secret("BARAQ_DATABASE_URL", os.environ.get("BARAQ_DATABASE_URL", ""))
if not DATABASE_URL:
    raise RuntimeError(
        "BARAQ requires BARAQ_DATABASE_URL. The SQLite fallback has "
        "been removed - set it to a postgresql:// URL via the DPAPI vault "
        "(recommended) or BARAQ_DATABASE_URL env var (e.g. "
        "postgresql+psycopg://user:pass@host:5432/baraq)."
    )
ECHO_SQL = False
EVENT_RETENTION_DAYS = 30

# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------
#: Seconds between host telemetry collection cycles. The scheduler polls the
#: local Windows event log / Sysmon / process / network sources on this
#: interval, so it is the minimum blind spot for the *local* collector. Remote
#: agents push telemetry in real time (see api/endpoints.py /ingest), so the
#: platform is real-time for fleet hosts; lower this to shrink the local blind
#: spot at the cost of more CPU. Floored at 5 s: the scheduler cycle also runs
#: tenant-wide detection + ML/risk sweeps, so sub-5s intervals risk DB
#: contention and CPU saturation with no real-time benefit (the agent push
#: path already covers sub-second ingest).
COLLECT_INTERVAL_SECONDS = max(5, int(os.environ.get("BARAQ_INTERVAL", "15")))
SCHEDULER_ENABLED = os.environ.get("BARAQ_SCHEDULER_ENABLED", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)
#: Test/dev isolation: when enabled, the alerting service still computes
#: findings but does NOT persist real alerts, notify, publish or stream them.
#: Use while exercising rules interactively (''pytest -k ...'', one-off
#: detection probes) so synthetic test traffic never pollutes the DB.
TEST_MODE = os.environ.get("BARAQ_TEST_MODE", "0").lower() in ("1", "true", "yes", "on")
EVENT_LOG_POLL_BATCH = 500
SECURITY_LOG_CHANNELS = ["Security", "System"]
POWERSHELL_CHANNELS = [
    "Microsoft-Windows-PowerShell/Operational",
    "Windows PowerShell",
]
# Extended channels for comprehensive endpoint detection (Phase 3)
APPLICATION_LOG_CHANNEL = ["Application"]
DEFENDER_LOG_CHANNEL = ["Microsoft-Windows-Windows Defender/Operational"]
FIREWALL_LOG_CHANNEL = [
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
]
WFP_LOG_CHANNEL = ["Microsoft-Windows-WFP/Operational"]
TASK_SCHEDULER_CHANNEL = ["Microsoft-Windows-TaskScheduler/Operational"]
TERMINAL_SERVICES_CHANNEL = [
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
]
WMI_ACTIVITY_CHANNEL = ["Microsoft-Windows-WMI-Activity/Operational"]
CODE_INTEGRITY_CHANNEL = ["Microsoft-Windows-CodeIntegrity/Operational"]
DRIVER_FRAMEWORKS_CHANNEL = [
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
]
GROUP_POLICY_CHANNEL = ["Microsoft-Windows-GroupPolicy/Operational"]
NTLM_LOG_CHANNEL = ["Microsoft-Windows-NTLM/Operational"]
KERBEROS_LOG_CHANNEL = ["Microsoft-Windows-Kerberos/Operational"]
PRINT_SERVICE_CHANNEL = ["Microsoft-Windows-PrintService/Operational"]
APPLOCKER_CHANNEL = ["Microsoft-Windows-AppLocker/Operational"]

#: All extended channels combined for the expanded collector
DNS_CLIENT_CHANNEL = ["Microsoft-Windows-DNS-Client/Operational"]
HARDWARE_EVENTS_CHANNEL = ["Hardware Events"]
USB_CHANNEL = ["Microsoft-Windows-Partition/Diagnostic"]
PRINT_SERVICE_FULL_CHANNEL = ["Microsoft-Windows-PrintService/Operational"]
BITLocker_CHANNEL = ["Microsoft-Windows-BitLocker-API/Management"]
DISK_CHANNEL = ["Microsoft-Windows-DiskDiagnostic/Operational"]
WINDOWS_DEFENDER_ALPHA_CHANNEL = ["Microsoft-Windows-Windows Defender/Operational"]
WINDOWS_FIREWALL_CONNECTION_CHANNEL = [
    "Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSuccess",
    "Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionFailure",
]

ALL_EXTENDED_CHANNELS = (
    APPLICATION_LOG_CHANNEL
    + DEFENDER_LOG_CHANNEL
    + FIREWALL_LOG_CHANNEL
    + WFP_LOG_CHANNEL
    + TASK_SCHEDULER_CHANNEL
    + TERMINAL_SERVICES_CHANNEL
    + WMI_ACTIVITY_CHANNEL
    + CODE_INTEGRITY_CHANNEL
    + DRIVER_FRAMEWORKS_CHANNEL
    + GROUP_POLICY_CHANNEL
    + NTLM_LOG_CHANNEL
    + KERBEROS_LOG_CHANNEL
    + PRINT_SERVICE_CHANNEL
    + APPLOCKER_CHANNEL
    + DNS_CLIENT_CHANNEL
    + HARDWARE_EVENTS_CHANNEL
    + USB_CHANNEL
    + PRINT_SERVICE_FULL_CHANNEL
    + BITLocker_CHANNEL
    + DISK_CHANNEL
    + WINDOWS_DEFENDER_ALPHA_CHANNEL
    + WINDOWS_FIREWALL_CONNECTION_CHANNEL
)

MAX_RAW_EVENT_SIZE = 64 * 1024

# --------------------------------------------------------------------------
# Feature toggles (roadmap "Recommended Lightweight Configuration").
# Everything defaults to ON so a standard install keeps current behaviour;
# set a flag to 0 to trade capability for lower resource usage.
# --------------------------------------------------------------------------
#: Async notification delivery (worker queue + retries + file fallback).
#: When 0, notifications dispatch on a plain per-alert thread (best-effort,
#: no retries, no fallback).
ASYNC_NOTIFY = os.environ.get("BARAQ_ASYNC_NOTIFY", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)
#: Incremental event-log collection (resume from the last record). When 0,
#: every cycle reads only the newest batch and earlier records are skipped.
INCREMENTAL_COLLECTION = os.environ.get(
    "BARAQ_INCREMENTAL_COLLECTION", "1"
).lower() not in (
    "0",
    "false",
    "no",
    "off",
)
#: Collector health registry + startup permission probe. When 0, the
#: /api/system/collectors/health endpoint reports empty statistics.
COLLECTOR_HEALTH = os.environ.get("BARAQ_COLLECTOR_HEALTH", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)
#: Cap on the number of native rules loaded by the rules engine (0 or
#: unset = all rules). Use to trim detection breadth on constrained hosts.
RULES_COUNT = max(0, int(os.environ.get("BARAQ_RULES_COUNT", "0")))
#: Multi-stage kill-chain correlation rule. When 0, the correlation rule is
#: excluded from the engine.
KILL_CHAIN = os.environ.get("BARAQ_KILL_CHAIN", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)
#: Per-rule overrides: JSON mapping ``rule_id`` -> ``{"enabled": bool,
#: "severity": "low|medium|high|critical", "confidence": float}``.
#: Only the keys you set are applied; unknown rule ids are ignored.
#: Example:
#:   BARAQ_RULE_OVERRIDES='{"brute_force": {"severity": "critical"}, "usb_device": {"enabled": false}}'
RULE_OVERRIDES: dict = {}
try:
    _overrides_raw = os.environ.get("BARAQ_RULE_OVERRIDES", "").strip()
    if _overrides_raw:
        parsed = json.loads(_overrides_raw)
        if isinstance(parsed, dict):
            RULE_OVERRIDES = parsed
except (
    ValueError,
    TypeError,
) as _exc:
    raise RuntimeError(f"BARAQ_RULE_OVERRIDES is not valid JSON: {_exc}") from _exc

# --------------------------------------------------------------------------
# Multi-node / deployment topology (roadmap 3.1)
# --------------------------------------------------------------------------
#: Process role: "all" (API + scheduler, single instance), "api" (API only,
#: scheduler disabled - run the scheduler as its own service elsewhere) or
#: "scheduler" (standalone scheduler service via backend/scheduler_service.py).
APP_ROLE = os.environ.get("BARAQ_ROLE", "all").lower().strip() or "all"
#: Redis URL for the distributed scheduler lock (e.g. redis://redis:6379/0).
#: When empty, the PostgreSQL advisory lock is used (single-writer for the
#: whole database). Set this to let several API replicas share one scheduler.
REDIS_URL = os.environ.get("BARAQ_REDIS_URL", "").strip()
#: Optional read-only PostgreSQL replica for query-heavy endpoints
#: (dashboards, event listing). When empty, all reads use the primary.
READONLY_DATABASE_URL = os.environ.get("BARAQ_READONLY_DATABASE_URL", "").strip()
#: Scheduler lock TTL in seconds (Redis path): the lock is re-armed
#: (heartbeat) while the scheduler cycle runs.
SCHEDULER_LOCK_TTL_SECONDS = max(
    10, int(os.environ.get("BARAQ_SCHEDULER_LOCK_TTL", "30"))
)
#: Audit trail retention in days (roadmap 3.3 compliance): audit entries are
#: hashed-chained, so they age out via a separate purge that runs alongside
#: telemetry retention. Default 365 days (regulatory-grade trail).
AUDIT_RETENTION_DAYS = max(30, int(os.environ.get("BARAQ_AUDIT_RETENTION_DAYS", "365")))
#: Agent fleet (roadmap 3.4): seconds without an ingest heartbeat before an
#: agent is marked stale / offline in the fleet overview.
AGENT_STALE_SECONDS = max(30, int(os.environ.get("BARAQ_AGENT_STALE_SECONDS", "300")))
AGENT_OFFLINE_SECONDS = max(
    60, int(os.environ.get("BARAQ_AGENT_OFFLINE_SECONDS", "3600"))
)

# New collector channels / sources (live only).
USB_EVENT_IDS = {6416, 6420}
SYSMON_CHANNELS = ["Microsoft-Windows-Sysmon/Operational"]
SIGNATURE_LIST = BUNDLE_DIR / "detection" / "signatures.json"
MAIL_INGEST_DIR = os.environ.get("BARAQ_MAIL_DIR", "")
MAIL_INGEST_EXTENSIONS = (".eml", ".msg", ".json")

#: Mark the session cookie Secure (requires HTTPS; set to 1 in production).
#: TLS_ENABLED below forces it to 1 automatically - see "Transport security".

# --------------------------------------------------------------------------
# CORS (Cross-Origin Resource Sharing)
# --------------------------------------------------------------------------
# SECURITY WARNING: The default CORS_ORIGINS below include localhost entries
# intended ONLY for local development. In production, you MUST restrict
# CORS origins to your actual domain(s) via BARAQ_CORS_ORIGINS to prevent
# unauthorized cross-origin requests. Allowing localhost in production
# enables CSRF-like attacks from any local process.

# --------------------------------------------------------------------------
# Detection tuning
# --------------------------------------------------------------------------
DETECTION_WINDOW_MINUTES = 10
BRUTE_FORCE_THRESHOLD = 5  # failed logons within window
BRUTE_FORCE_ACCOUNTS = 1  # distinct accounts to consider
PORT_SCAN_DISTINCT_PORTS = 20  # distinct ports probed by one source
# Wider than the old 120s default: a 120s window let slow / distributed scans
# interleaved with normal traffic fall below the distinct-port threshold and
# evade detection (see documentation/red_team_validation.md false-negative #5).
PORT_SCAN_WINDOW_SECONDS = 300
HONEYPOT_ACCOUNT_PREFIXES = ("administrator", "admin", "sa", "root")
#: Directory of Sigma (SigmaHQ) rule YAML files. Empty/missing disables the
#: Sigma engine. Populate with scripts/sigma_pull.py (3000+ community rules).
#: Frozen builds ship the rules as a bundle resource (BUNDLE_DIR); fall back
#: to the writable app dir for source/dev and legacy exe layouts.
SIGMA_RULES_DIR = Path(
    os.environ.get(
        "SIGMA_RULES_DIR",
        str(
            (BUNDLE_DIR / "sigma_rules")
            if FROZEN and (BUNDLE_DIR / "sigma_rules").exists()
            else APP_DIR / "sigma_rules"
        ),
    )
)

# --------------------------------------------------------------------------
# Alert aggregation / escalation
# --------------------------------------------------------------------------
#: How many re-triggers of the same open alert escalate its severity.
ALERT_ESCALATE_AFTER = 5
#: Severity ladder used for repeat-trigger escalation.
SEVERITY_LADDER = ("low", "medium", "high", "critical")
#: Alert throttling: no more than ALERT_THROTTLE_MAX_PER_WINDOW new alerts per
#: rule within ALERT_THROTTLE_MINUTES minutes (excess findings refresh the most
#: recent open alert instead of opening new ones).
ALERT_THROTTLE_MINUTES = 5
ALERT_THROTTLE_MAX_PER_WINDOW = 5
ALERT_RETRIGGER_COOLDOWN_SECONDS = max(
    0, int(os.environ.get("BARAQ_ALERT_RETRIGGER_COOLDOWN_SECONDS", "30"))
)

# --------------------------------------------------------------------------
# ML lifecycle (retraining / staleness)
# --------------------------------------------------------------------------
ML_RETRAIN_AFTER_MINUTES = int(
    os.environ.get("BARAQ_ML_RETRAIN_AFTER_MINUTES", "5")
)  # model older than this (minutes) is stale
ML_RETRAIN_MIN_NEW_EVENTS = int(
    os.environ.get("BARAQ_ML_RETRAIN_MIN_NEW_EVENTS", "200")
)  # ...or more new events since training
ML_RETRAIN_MIN_NEW_VERDICTS = int(
    os.environ.get("BARAQ_ML_RETRAIN_MIN_NEW_VERDICTS", "5")
)  # ...or N analyst verdicts since training
ML_META_FILE = Path(
    os.environ.get(
        "BARAQ_ML_META_FILE",
        (PROJECT_ROOT / "database" / "model_meta.json").as_posix(),
    )
)
#: Version of the event feature space; persisted bundles with a different
#: version are ignored and a clean retrain is forced.
ML_FEATURE_VERSION = 7
#: Persisted model bundle (Isolation Forests + supervised + thresholds).
ML_MODEL_BUNDLE = Path(
    os.environ.get(
        "BARAQ_ML_MODEL_BUNDLE",
        (Path(ML_META_FILE).parent / "model.bundle.joblib").as_posix(),
    )
)
#: Label-free threshold target: the per-stream anomaly threshold is the
#: ``(1 - ML_TARGET_FPR)`` quantile of the training score distribution, so the
#: detector flags ~ML_TARGET_FPR of the locally-learned baseline while still
#: catching distribution tails (constant-false-alarm-rate calibration).
ML_TARGET_FPR = float(os.environ.get("BARAQ_ML_TARGET_FPR", "0.10"))

#: Per-stream false-positive rate budgets. Login events are frequent so keep
#: FPR low; process/network events are rarer so tolerate more FPR for recall.
#: JSON map like {"login": 0.05, "process": 0.15, "network": 0.10}.
try:
    _env_stream_fpr = json.loads(os.environ.get("BARAQ_ML_STREAM_FPR", "{}") or "{}")
except (ValueError, TypeError):
    _env_stream_fpr = {}
ML_STREAM_FPR: dict[str, float] = {
    "login": float(_env_stream_fpr.get("login", 0.05)),
    "process": float(_env_stream_fpr.get("process", 0.15)),
    "network": float(_env_stream_fpr.get("network", 0.10)),
}

#: Deployment mode for the ML layer.  The default is deliberately
#: ``advisory``: event scores may influence analyst-facing risk, but the ML
#: layer never triggers a response action on its own.  ``shadow`` stores
#: candidate scores for monitoring without setting ``is_anomaly``/``ml_score``
#: on events.  ``off`` disables scoring entirely.  There is intentionally no
#: ``enforce`` mode until a model carries a validated campaign-held-out
#: manifest (see docs/ml-deployment-readiness.md).
ML_DEPLOYMENT_MODES = ("off", "shadow", "advisory")
ML_DEPLOYMENT_MODE = os.environ.get("BARAQ_ML_DEPLOYMENT_MODE", "advisory").strip().lower()
if ML_DEPLOYMENT_MODE not in ML_DEPLOYMENT_MODES:
    # Fail closed to shadow rather than silently enabling an unknown mode.
    ML_DEPLOYMENT_MODE = "shadow"

#: Checksummed deployment manifest written by
#: ``scripts/ml_deployment_gate.py``.  Missing manifest => no enforcement;
#: an unreadable/blocked manifest downgrades scoring to shadow.
ML_MANIFEST_FILE = Path(
    os.environ.get(
        "BARAQ_ML_MANIFEST_FILE",
        (Path(ML_META_FILE).parent / "model_manifest.json").as_posix(),
    )
)

#: How long shadow scores are retained by the normal telemetry retention pass.
ML_SHADOW_RETENTION_DAYS = max(
    1, int(os.environ.get("BARAQ_ML_SHADOW_RETENTION_DAYS", "7"))
)

# --------------------------------------------------------------------------
# ML drift guard (anti "attacker becomes normal")
# --------------------------------------------------------------------------
#: When more than this fraction of recent *scored* events lands above the
#: per-stream anomaly threshold, the detector is considered drifted (the
#: learned baseline no longer reflects the live distribution) and is marked
#: stale so the scheduler retrains and the operator sees the drift signal.
ML_DRIFT_RATE = float(os.environ.get("BARAQ_ML_DRIFT_RATE", "0.75"))
#: Minimum number of recently scored events required before a drift verdict
#: can be produced (avoids deciding on noise).
ML_DRIFT_MIN_SAMPLES = int(os.environ.get("BARAQ_ML_DRIFT_MIN_SAMPLES", "40"))
#: Roadmap 4.1 - PSI drift monitor: per-stream PSI above this is "watch"
#: (worth an incremental retrain), above ML_DRIFT_RATE is "drift".
ML_PSI_WATCH = float(os.environ.get("BARAQ_ML_PSI_WATCH", "0.10"))
#: Online learning: incremental retrain window in hours + minimum new analyst
#: verdicts before a scheduled incremental update runs.
ML_INCREMENTAL_HOURS = max(1, int(os.environ.get("BARAQ_ML_INCREMENTAL_HOURS", "6")))
ML_INCREMENTAL_MIN_VERDICTS = max(
    1, int(os.environ.get("BARAQ_ML_INCREMENTAL_MIN_VERDICTS", "5"))
)
#: Online learning: buffer size for sliding-window features (per stream).
ML_ONLINE_BUFFER_SIZE = max(
    512, int(os.environ.get("BARAQ_ML_ONLINE_BUFFER_SIZE", "2048"))
)
#: Online learning: minimum new events before triggering an incremental update.
ML_ONLINE_MIN_NEW_EVENTS = max(
    10, int(os.environ.get("BARAQ_ML_ONLINE_MIN_NEW_EVENTS", "50"))
)
#: Online learning: minimum new verdicts before triggering an incremental update.
ML_ONLINE_MIN_NEW_VERDICTS = max(
    1, int(os.environ.get("BARAQ_ML_ONLINE_MIN_NEW_VERDICTS", "5"))
)
#: Online learning: minimum minutes between incremental updates.
ML_ONLINE_UPDATE_INTERVAL = max(
    5, int(os.environ.get("BARAQ_ML_ONLINE_UPDATE_INTERVAL", "15"))
)
#: Model versioning (4.1): how many training runs are kept in the version
#: history (meta file); the previous model bundle is always kept for A/B.
ML_VERSION_HISTORY = max(2, int(os.environ.get("BARAQ_ML_VERSION_HISTORY", "10")))
# --------------------------------------------------------------------------
# ML bootstrap (day-1 cold start)
# --------------------------------------------------------------------------
#: When no locally-trained bundle exists (fresh deployment), load the bundled
#: bootstrap model trained on a deterministic synthetic corpus, so detection
#: is never blind on day 1. The first real retrain supersedes it.
ML_BOOTSTRAP_ENABLED = os.environ.get(
    "BARAQ_ML_BOOTSTRAP_ENABLED", "1"
).lower() not in ("0", "false", "no")
#: Shipped-with-product seed bundle (trained offline via
#: ``tools/build_bootstrap_model.py``).
ML_BOOTSTRAP_BUNDLE = Path(
    os.environ.get(
        "BARAQ_ML_BOOTSTRAP_BUNDLE",
        (Path(__file__).parent / "ml" / "assets" / "bootstrap_model.joblib").as_posix(),
    )
)
#: The bundled bootstrap model is a DETERMINISTIC SYNTHETIC corpus. It guarantees
#: day-1 coverage but does not reflect a given environment's behaviour. Once
#: ``ML_TRAIN_MIN_SAMPLES`` real events have been collected, the scheduler
#: retrains on real telemetry and the synthetic model is superseded. Set
#: ``BARAQ_ML_ALLOW_BOOTSTRAP=0`` to refuse the synthetic model entirely - the
#: platform will stay untrained until enough REAL telemetry is collected (closes
#: the "ML trained only on synthetic data" gap for high-assurance deployments).
ML_ALLOW_BOOTSTRAP = os.environ.get("BARAQ_ML_ALLOW_BOOTSTRAP", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)
#: Validate detection against REAL host telemetry, not just synthetic fixtures:
#: the hold-out endpoint (``/api/evaluation/holdout?use_real_baseline=true``) and
#: ``scripts/validate_realworld.py`` use live collectors for the negative class.
ML_VALIDATE_ON_REAL = os.environ.get("BARAQ_ML_VALIDATE_ON_REAL", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)

# --------------------------------------------------------------------------
# ML tuning
# --------------------------------------------------------------------------
ML_CONTAMINATION = 0.05
ML_TRAIN_MIN_SAMPLES = 30
ML_RANDOM_STATE = 42

# --------------------------------------------------------------------------
# Risk / scoring weights
# --------------------------------------------------------------------------
SEVERITY_SCORES = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
SECURITY_SCORE_START = 100
SECURITY_SCORE_PENALTY = {"critical": 14, "high": 8, "medium": 4, "low": 1}

# --------------------------------------------------------------------------
# Hybrid risk scoring (rule-based detection vs ML anomaly detection)
# --------------------------------------------------------------------------
ML_RULE_WEIGHT = 0.6
ML_DETECTION_WEIGHT = 0.4
RISK_LEVEL_MEDIUM = 40
RISK_LEVEL_HIGH = 65
RISK_LEVEL_CRITICAL = 85

# --------------------------------------------------------------------------
# Entity Risk-Based Alerting (RBA)
# --------------------------------------------------------------------------
# Persistent risk accumulates per entity (user / host / ip) across every
# detection and decays exponentially over time; crossing a threshold raises
# an escalated "entity notable" alert that links the contributing findings.
ENTITY_RISK_ENABLED = os.environ.get("BARAQ_ENTITY_RISK", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)
#: Exponential-decay half-life in days (score 90 today -> ~45 after one
#: half-life, -> ~22 after two). 7 days mirrors the default risk window.
ENTITY_RISK_DECAY_DAYS = max(
    0.1, float(os.environ.get("BARAQ_ENTITY_RISK_DECAY_DAYS", "7"))
)
#: Score thresholds at which an entity becomes MEDIUM / HIGH / CRITICAL.
ENTITY_RISK_LEVEL_MEDIUM = float(
    os.environ.get("BARAQ_ENTITY_RISK_MEDIUM", str(RISK_LEVEL_MEDIUM))
)
ENTITY_RISK_LEVEL_HIGH = float(
    os.environ.get("BARAQ_ENTITY_RISK_HIGH", str(RISK_LEVEL_HIGH))
)
ENTITY_RISK_LEVEL_CRITICAL = float(
    os.environ.get("BARAQ_ENTITY_RISK_CRITICAL", str(RISK_LEVEL_CRITICAL))
)
#: Per-rule risk modifiers ("risk modifiers"): JSON mapping rule_id ->
#: multiplier applied to that rule's score contribution, e.g.
#:   BARAQ_RULE_RISK_WEIGHTS='{"brute_force": 2.0, "usb_device": 0.5}'
RULE_RISK_WEIGHTS: dict = {}
try:
    _risk_weights_raw = os.environ.get("BARAQ_RULE_RISK_WEIGHTS", "").strip()
    if _risk_weights_raw:
        _parsed_weights = json.loads(_risk_weights_raw)
        if isinstance(_parsed_weights, dict):
            RULE_RISK_WEIGHTS = {str(k): float(v) for k, v in _parsed_weights.items()}
except (ValueError, TypeError) as _exc:
    raise RuntimeError(f"BARAQ_RULE_RISK_WEIGHTS is not valid JSON: {_exc}") from _exc
#: Reopen window for entity-risk notables: an escalated notable alert for an
#: entity is only opened once within this window even if the score keeps
#: climbing (updates refresh the open alert instead of spamming).
ENTITY_RISK_NOTABLE_WINDOW_HOURS = max(
    1, int(os.environ.get("BARAQ_ENTITY_RISK_NOTABLE_WINDOW_HOURS", "6"))
)

# --------------------------------------------------------------------------
# Declarative correlation engine
# --------------------------------------------------------------------------
#: Directory of YAML correlation rules (see backend/detection/correlation.py).
#: Every ``*.yml`` / ``*.yaml`` file here is loaded and evaluated by the
#: engine; analysts add multi-stage detection without writing code.
CORRELATION_RULES_DIR = Path(
    os.environ.get(
        "CORRELATION_RULES_DIR",
        str(
            (BUNDLE_DIR / "detection" / "correlation_rules")
            if FROZEN and (BUNDLE_DIR / "detection" / "correlation_rules").exists()
            else APP_DIR / "backend" / "detection" / "correlation_rules"
        ),
    )
)

# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 8001
#: HTTPS port used by `start.bat secure` (and the LAN/HTTPS launcher).
TLS_PORT = 8443
_cors_raw = os.environ.get("BARAQ_CORS_ORIGINS", "")
CORS_ORIGINS = (
    [o.strip() for o in _cors_raw.split(",") if o.strip()]
    if _cors_raw
    else [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8001",
        "http://127.0.0.1:8001",
    ]
)
if not CORS_ORIGINS:
    CORS_ORIGINS = ["http://localhost:5173"]
if any("localhost" in o for o in CORS_ORIGINS):
    logger.warning("CORS origins contain localhost - restrict for production")

# --------------------------------------------------------------------------
# Transport security (TLS)
# --------------------------------------------------------------------------
#: Enable HTTPS by serving uvicorn with --ssl-certfile/--ssl-keyfile. When on,
#: the session cookie is forced to Secure automatically.
TLS_ENABLED = os.environ.get("BARAQ_TLS", "0").lower() in ("1", "true", "yes", "on")
#: PEM certificate / private key paths (generated by scripts/gen_cert.ps1).
TLS_CERT_FILE = os.environ.get(
    "BARAQ_TLS_CERT", (APP_DIR / "certs" / "baraq.crt").as_posix()
)
TLS_KEY_FILE = os.environ.get(
    "BARAQ_TLS_KEY", (APP_DIR / "certs" / "baraq.key").as_posix()
)
#: When TLS is enabled the cookie MUST be Secure — never honours the env override.
COOKIE_SECURE = TLS_ENABLED or os.environ.get("BARAQ_COOKIE_SECURE", "0").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# --------------------------------------------------------------------------
# Commercial licensing
# --------------------------------------------------------------------------
#: Ed25519 public key (base64url) used to verify BARAQ license keys. The
#: matching private key stays with the vendor (licensing/private_key.pem,
#: gitignored) and is never shipped. Override for a new product key chain.
LICENSE_PUBLIC_KEY = os.environ.get("BARAQ_LICENSE_PUBLIC_KEY", "")
if not LICENSE_PUBLIC_KEY:
    logger.warning("BARAQ_LICENSE_PUBLIC_KEY not set - license verification disabled")
#: Free-trial length in days before a valid license key is required.
TRIAL_DAYS = int(os.environ.get("BARAQ_TRIAL_DAYS", "30"))
#: Product version reported by /api/system/update/check and the API.
APP_VERSION = os.environ.get("BARAQ_VERSION", "1.0.0")

#: Maximum accepted request body, in bytes. Requests with a Content-Length
#: above this (or that grow beyond it while streaming) are rejected with 413
#: before any handler runs. Keeps oversized JSON/upload payloads from being
#: parsed or persisted (mitigates decompression/alloc abuse).
MAX_REQUEST_BYTES = int(
    os.environ.get("BARAQ_MAX_REQUEST_BYTES", str(16 * 1024 * 1024))
)
#: CSRF protection for cookie-authenticated sessions (double-submit pattern):
#: state-changing requests made with the session cookie must echo the
#: ``baraq_csrf`` cookie value in the ``X-CSRF-Token`` header. API-key and
#: Bearer-header callers are unaffected (cross-site browsers cannot set those
#: headers), so this can stay enabled alongside legacy clients.
CSRF_ENABLED = os.environ.get("BARAQ_CSRF_ENABLED", "1").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
if not CSRF_ENABLED:
    logger.warning("CSRF PROTECTION DISABLED - set BARAQ_CSRF_ENABLED=1 for production")

# --------------------------------------------------------------------------
# API hardening (roadmap 5.3)
# --------------------------------------------------------------------------
#: Emit standard security headers on every HTTP response
#: (X-Content-Type-Options / X-Frame-Options / Referrer-Policy /
#: Permissions-Policy / Content-Security-Policy). Disable only for
#: reverse-proxy setups that add their own headers.
SECURITY_HEADERS = os.environ.get("BARAQ_SECURITY_HEADERS", "1").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
#: HSTS max-age (seconds). Only meaningful with TLS; the header is emitted
#: unconditionally but browsers ignore it on plain HTTP.
HSTS_MAX_AGE = int(os.environ.get("BARAQ_HSTS_MAX_AGE", str(60 * 60 * 24 * 180)))
#: API rate limiting: max requests per client (API key, else IP) per minute,
#: with a burst allowance before the fixed window kicks in. 0 disables.
API_RATE_LIMIT = int(os.environ.get("BARAQ_API_RATE_LIMIT", "600"))
API_RATE_BURST = int(os.environ.get("BARAQ_API_RATE_BURST", "900"))
#: Optional network ACLs: comma-separated CIDRs. An empty whitelist means
#: "allow everyone" (normal operation); when set, only those networks may
#: reach the API (agents must be inside them). The blocklist is applied
#: first and wins over the whitelist.
API_IP_WHITELIST = [
    p.strip()
    for p in os.environ.get("BARAQ_API_IP_WHITELIST", "").split(",")
    if p.strip()
]
API_IP_BLOCKLIST = [
    p.strip()
    for p in os.environ.get("BARAQ_API_IP_BLOCKLIST", "").split(",")
    if p.strip()
]

# --------------------------------------------------------------------------
# Encryption at rest
# --------------------------------------------------------------------------
#: Encrypt sensitive free-text fields (messages, evidence, command lines,
#: email bodies, chat, audit details) with AES-256-GCM before storage.
#: Default ON for the packaged executable, OFF for source/dev runs unless
#: explicitly enabled. Key lives in the DPAPI vault (secrets.dat).
ENCRYPT_AT_REST = FROZEN or os.environ.get("BARAQ_ENCRYPT_AT_REST", "1").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
#: Vault key name under which the AES master key is stored.
ENCRYPTION_KEY_NAME = "BARAQ_ENCRYPTION_KEY"

# --------------------------------------------------------------------------
# Authentication / RBAC
# --------------------------------------------------------------------------
# When enabled, every /api/* request must present a valid API key via the
# `X-API-Key` header. Roles: "analyst" (read + standard ops) / "admin".
# Keys are configured as a JSON map {"key": "role"}; a development default
# is provided so the dashboard works out of the box.
AUTH_ENABLED = os.environ.get("BARAQ_AUTH_ENABLED", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)

_DEFAULT_API_KEYS: dict[str, str] = {}


# --------------------------------------------------------------------------
# Ticketing integrations (roadmap 6.3): Jira + ServiceNow
# --------------------------------------------------------------------------
#: Dispatch alerts to external ticketing only when severity >= this rank
#: (critical > high > medium > low > info).
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
INTEGRATIONS_MIN_SEVERITY = os.environ.get("BARAQ_INTEGRATIONS_MIN_SEVERITY", "high")
#: Jira (REST v2). ``JIRA_API_TOKEN`` is a PAT or the password for the
#: ``JIRA_EMAIL`` basic-auth account.
JIRA_URL = os.environ.get("BARAQ_JIRA_URL", "")
JIRA_EMAIL = os.environ.get("BARAQ_JIRA_EMAIL", "")
JIRA_API_TOKEN = _secret("BARAQ_JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("BARAQ_JIRA_PROJECT_KEY", "")
JIRA_ISSUE_TYPE = os.environ.get("BARAQ_JIRA_ISSUE_TYPE", "Task")
#: ServiceNow (REST table API). ``SERVICENOW_INSTANCE`` is the subdomain,
#: e.g. ``acme`` for https://acme.service-now.com.
SERVICENOW_INSTANCE = os.environ.get("BARAQ_SERVICENOW_INSTANCE", "")
SERVICENOW_USERNAME = os.environ.get("BARAQ_SERVICENOW_USERNAME", "")
SERVICENOW_PASSWORD = _secret("BARAQ_SERVICENOW_PASSWORD", "")
SERVICENOW_TABLE = os.environ.get("BARAQ_SERVICENOW_TABLE", "incident")

try:
    _env_keys = json.loads(_secret("BARAQ_API_KEYS", "{}") or "{}")
except (ValueError, TypeError):
    _env_keys = {}
#: Configured API keys. When BARAQ_API_KEYS is set, it fully replaces the
#: public development defaults so the shipped keys can never stay valid.
API_KEYS: dict[str, str] = (
    {str(k): str(v) for k, v in _env_keys.items()}
    if _env_keys
    else dict(_DEFAULT_API_KEYS)
)

#: Allow the public development keys (baraq-dev-*) to authenticate. In
#: production they are always rejected regardless of this flag; elsewhere set
#: BARAQ_ALLOW_DEV_KEYS=1 to opt-in to the well-known keys. The dashboard
#: setup banner warns while they are accepted. Disabled by default for security.
ALLOW_DEV_KEYS = (not IS_PRODUCTION) and os.environ.get(
    "BARAQ_ALLOW_DEV_KEYS", "0"
).lower() in ("1", "true", "yes", "on")
_USING_DEV_KEYS = not _env_keys or any(
    str(key).startswith("baraq-dev-") for key in _env_keys
)
if _USING_DEV_KEYS and not ALLOW_DEV_KEYS:
    raise RuntimeError(
        "Public development API keys (baraq-dev-*) are disabled via "
        "BARAQ_ALLOW_DEV_KEYS=0. Configure BARAQ_API_KEYS in .env before starting."
    )

#: Secret used to sign session tokens (override via BARAQ_TOKEN_SECRET).
AUTH_TOKEN_SECRET = _secret("BARAQ_TOKEN_SECRET", "")
#: True when AUTH_TOKEN_SECRET was auto-generated in-process rather than
#: supplied via the environment, .env, or the DPAPI vault. A new random
#: value is generated every restart, which silently invalidates every
#: outstanding session token.
AUTH_TOKEN_SECRET_AUTO_GENERATED = not _secret("BARAQ_TOKEN_SECRET", "")
if AUTH_TOKEN_SECRET_AUTO_GENERATED and not IS_PRODUCTION:
    import secrets as _secrets

    AUTH_TOKEN_SECRET = _secrets.token_hex(32)
    # Logged lazily: this module is imported before the application's
    # logging config is set up. The warning fires once at import time
    # and is captured by whatever handler is attached later.
    import logging as _logging

    _logging.getLogger("baraq.config").warning(
        "BARAQ_TOKEN_SECRET was not provided; a random 32-byte value "
        "was generated for THIS process. Every restart will invalidate "
        "all outstanding session tokens. Set BARAQ_TOKEN_SECRET in .env "
        "or the DPAPI vault for any non-ephemeral deployment."
    )
#: True once the admin password and API keys are configured (via vault/.env or
#: the environment), i.e. the public development defaults are no longer in force.
SECRETS_CONFIGURED = bool(_secret("BARAQ_ADMIN_PASSWORD") and _secret("BARAQ_API_KEYS"))
#: Bootstrap admin that is seeded into the users table on first startup.
ADMIN_USERNAME = os.environ.get("BARAQ_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = _secret("BARAQ_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)

#: Require every admin account to have TOTP enrolled before admin API
#: operations are allowed (default on in production). Analyst logins and the
#: MFA enrollment endpoints themselves stay accessible so a fresh deploy can
#: still be secured on first boot.
ENFORCE_ADMIN_MFA = os.environ.get(
    "BARAQ_ENFORCE_ADMIN_MFA", "0"
).lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------
# Production-mode gate
# --------------------------------------------------------------------------
def _assert_production_safe() -> None:
    """Refuse to boot with insecure defaults when ``BARAQ_ENV=production``.

    The development defaults (public dev API keys, hardcoded session secret,
    well-known admin password, auth/CSRF toggles) are convenient for a lab but
    are not acceptable for an operator-facing deployment. Each check names the
    exact environment variable to fix, so a failed boot is self-explanatory.
    """
    if not IS_PRODUCTION:
        return
    if not SECRETS_CONFIGURED:
        raise RuntimeError(
            "Production mode (BARAQ_ENV=production) requires configured "
            "credentials: set BARAQ_ADMIN_PASSWORD and BARAQ_API_KEYS "
            "via the environment, .env or the DPAPI vault before starting."
        )
    if ADMIN_PASSWORD in (INSECURE_BOOTSTRAP_PASSWORD, ""):
        raise RuntimeError(
            "Production mode refuses the well-known bootstrap password. Set "
            "BARAQ_ADMIN_PASSWORD to a strong unique value before starting."
        )
    if _USING_DEV_KEYS:
        raise RuntimeError(
            "Production mode refuses the public development API keys "
            "(baraq-dev-*). Configure a private BARAQ_API_KEYS value."
        )
    if not AUTH_TOKEN_SECRET:
        raise RuntimeError(
            "Production mode requires a unique session secret: set "
            "BARAQ_TOKEN_SECRET in your environment or .env file."
        )
    if not AUTH_ENABLED:
        raise RuntimeError("Production mode forbids BARAQ_AUTH_ENABLED=0.")
    if not CSRF_ENABLED:
        raise RuntimeError("Production mode forbids BARAQ_CSRF_ENABLED=0.")
    if not THREAT_INTEL_ENABLED:
        raise RuntimeError(
            "Production mode requires threat intelligence: set "
            "BARAQ_THREAT_INTEL_ENABLED=1 (the disabled default is a "
            "development convenience)."
        )
    if any("localhost" in o for o in CORS_ORIGINS):
        raise RuntimeError(
            "Production mode forbids localhost in BARAQ_CORS_ORIGINS. "
            "Set CORS origins to your actual domain(s)."
        )
    if not ENCRYPT_AT_REST:
        raise RuntimeError(
            "Production mode requires BARAQ_ENCRYPT_AT_REST=1."
        )
    if SOAR_DESTRUCTIVE_ACTIONS_ENABLED:
        raise RuntimeError(
            "Production mode refuses destructive SOAR actions by default. "
            "Set BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED=0."
        )
    if METRICS_PUBLIC:
        raise RuntimeError(
            "Production mode requires BARAQ_METRICS_PUBLIC=0."
        )
    db_url = DATABASE_URL
    if "password" in db_url.lower() or "123" in db_url:
        import warnings as _w
        _w.warn(
            "BARAQ: Database URL contains a weak/default password! "
            "Change it before deploying to any network.",
            stacklevel=2,
        )


# --------------------------------------------------------------------------
# LDAP / Active Directory SSO (SC5b)
# --------------------------------------------------------------------------
#: Authenticate operators against an external directory (opt-in).
LDAP_ENABLED = os.environ.get("BARAQ_LDAP_ENABLED", "0").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
#: Directory URL: ldap://host[:389] or ldaps://host[:636].
LDAP_URL = os.environ.get("BARAQ_LDAP_URL", "")
#: Service account used to search the directory (anonymous if empty).
#: Password comes from the vault first (see ``_secret``), then the environment.
LDAP_BIND_DN = _secret("BARAQ_LDAP_BIND_DN", "")
LDAP_BIND_PASSWORD = _secret("BARAQ_LDAP_BIND_PASSWORD", "")
#: Search base for user lookups, e.g. DC=corp,DC=local.
LDAP_BASE_DN = os.environ.get("BARAQ_LDAP_BASE_DN", "")
#: Filter locating a user by login name; ``{username}`` is substituted.
LDAP_USER_FILTER = os.environ.get(
    "BARAQ_LDAP_USER_FILTER",
    "(&(objectClass=person)(sAMAccountName={username}))",
)
#: Attribute holding the display name (fallback: CN / user name).
LDAP_NAME_ATTRIBUTE = os.environ.get("BARAQ_LDAP_NAME_ATTRIBUTE", "displayName")
#: Group names (exact, case-insensitive) granting the admin role in both the
#: LDAP (``backend/ldap.py::_role_for``) and OIDC
#: (``backend/oidc.py::profile_from_claims``) SSO adapters.
#:
#: Matching is intentionally EXACT (case-insensitive) — a group whose name
#: merely contains 'admin' (e.g. ``Administrators (Read-Only)``,
#: ``not-admin-but-related``, ``BARAQ Admins Pager``) is NOT promoted to
#: admin. Substring matching was removed because it was a privilege-
#: escalation primitive against IdPs whose group names are loosely
#: classified. Operators must opt in to admin by listing the canonical
#: group CN.
LDAP_ADMIN_GROUPS = [
    g.strip()
    for g in os.environ.get(
        "BARAQ_LDAP_ADMIN_GROUPS", "Domain Admins,BARAQ Admins"
    ).split(",")
    if g.strip()
]
#: Seconds to wait for directory connect/search before failing.
LDAP_SEARCH_TIMEOUT = int(os.environ.get("BARAQ_LDAP_SEARCH_TIMEOUT", "10"))

# --------------------------------------------------------------------------
# OpenID Connect SSO (SC5c)
# --------------------------------------------------------------------------
#: Authenticate operators via an OpenID Provider (opt-in). Requires
#: BARAQ_OIDC_ISSUER, BARAQ_OIDC_CLIENT_ID and (by default) a secret.
OIDC_ENABLED = os.environ.get("BARAQ_OIDC_ENABLED", "0").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
#: Issuer URL (discovery at <issuer>/.well-known/openid-configuration).
OIDC_ISSUER = os.environ.get("BARAQ_OIDC_ISSUER", "")
#: OAuth2 client credentials (client secret preferred in the vault).
OIDC_CLIENT_ID = _secret("BARAQ_OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = _secret("BARAQ_OIDC_CLIENT_SECRET", "")
#: Space-separated scope list requested at the authorization endpoint.
OIDC_SCOPES = os.environ.get("BARAQ_OIDC_SCOPES", "openid profile email")
#: Public path that completes the flow (frontend browser is redirected here).
OIDC_REDIRECT_PATH = os.environ.get(
    "BARAQ_OIDC_REDIRECT_PATH", "/api/auth/oidc/callback"
)
#: Groups claim carrying role groups (e.g. "groups"). The admin list reuses
#: LDAP_ADMIN_GROUPS so one config controls role mapping for both providers.
OIDC_GROUP_CLAIM = os.environ.get("BARAQ_OIDC_GROUP_CLAIM", "groups")
#: Claim carrying a display name (fallback: "name", then the sub value).
OIDC_NAME_CLAIM = os.environ.get("BARAQ_OIDC_NAME_CLAIM", "full_name")
#: Clock-skew allowed when validating id_token "exp"/"iat"/"nbf" (seconds).
OIDC_CLOCK_SKEW = int(os.environ.get("BARAQ_OIDC_CLOCK_SKEW", "30"))

# --------------------------------------------------------------------------
# Centralized logging / SIEM forwarding
# --------------------------------------------------------------------------
#: Output format: "json" (SIEM-friendly) or "text" (human console).
LOG_FORMAT = os.environ.get("BARAQ_LOG_FORMAT", "text")
#: Optional remote syslog (SIEM) collector. Leave empty to disable.
#: UDP RFC3164 (default) or TCP RFC5424 via BARAQ_SYSLOG_PROTO=tcp.
SYSLOG_HOST = os.environ.get("BARAQ_SYSLOG_HOST", "")
SYSLOG_PORT = int(os.environ.get("BARAQ_SYSLOG_PORT", "514"))
SYSLOG_PROTO = os.environ.get("BARAQ_SYSLOG_PROTO", "udp").lower()

# --------------------------------------------------------------------------
# Observability (roadmap 5.2): SLOs + optional OpenTelemetry export
# --------------------------------------------------------------------------
#: Prometheus-visible service-level objectives; the metrics endpoint renders
#: these next to the live SLO health gauges so Grafana alerts can burn.
#: Format: "name=window=target" pairs, e.g. "availability=30d=0.99,
#: freshness=24h=0.95, throughput=7d=0.9".
SLO_DEFINITIONS = [
    part.strip()
    for part in os.environ.get(
        "BARAQ_SLO_DEFINITIONS",
        "availability=30d=0.99,freshness=24h=0.95,alert_volume=7d=0.9",
    ).split(",")
    if part.strip()
]
#: OpenTelemetry OTLP/HTTP exporter endpoint (e.g. http://collector:4318).
#: When set AND the ``opentelemetry-*`` packages are installed, BARAQ exports
#: traces + metrics to the collector; otherwise the module is a no-op and the
#: platform runs untouched (same lazy pattern as Celery / Neo4j).
OTEL_ENDPOINT = os.environ.get("BARAQ_OTEL_ENDPOINT", "")
#: Include audit-trail entries in the syslog stream (recommended ON for SIEM).
SYSLOG_AUDIT = os.environ.get("BARAQ_SYSLOG_AUDIT", "1").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
ORGANIZATION_NAME = "BARAQ Prototype Lab"
ANALYST_NAME = "BARAQ Analyst"

# --------------------------------------------------------------------------
# Notifications (opt-in)
# --------------------------------------------------------------------------
# Generic webhook URL (JSON POST) and/or SMTP relay. Leave empty to disable.
# NOTIFY_MIN_SEVERITY: low | medium | high | critical
WEBHOOK_URL = os.environ.get("BARAQ_WEBHOOK_URL", "")
SMTP_HOST = os.environ.get("BARAQ_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("BARAQ_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("BARAQ_SMTP_USERNAME", "")
# Enforce STARTTLS encryption for SMTP (port 587). Set 0 only for local-only relays.
SMTP_STARTTLS = os.environ.get("BARAQ_SMTP_STARTTLS", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)
SMTP_FROM = os.environ.get("BARAQ_SMTP_FROM", "baraq@localhost")
SMTP_TO = os.environ.get("BARAQ_SMTP_TO", "")
SMTP_PASSWORD = _secret("BARAQ_SMTP_PASSWORD", "")
NOTIFY_MIN_SEVERITY = os.environ.get("BARAQ_NOTIFY_MIN_SEVERITY", "high")
#: Per-channel floors. A phone should only ring for a critical (otherwise
#: analysts learn to ignore it), while email/webhook can take the high tier.
#: Empty => fall back to BARAQ_NOTIFY_MIN_SEVERITY.
TELEGRAM_MIN_SEVERITY = os.environ.get("BARAQ_TELEGRAM_MIN_SEVERITY", "")
WEBHOOK_MIN_SEVERITY = os.environ.get("BARAQ_WEBHOOK_MIN_SEVERITY", "")
# Telegram push (bot). Bot token is stored in the vault/secret env; chat id
# is a number (or @channelusername). Leave empty to disable.
TELEGRAM_BOT_TOKEN = _secret("BARAQ_TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("BARAQ_TELEGRAM_CHAT_ID", "")
# Windows toast notifications (PowerShell helper; best-effort).
TOAST_ENABLED = os.environ.get("BARAQ_TOAST_ENABLED", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)
# Notification delivery: retries per channel (exponential backoff) and the
# directory where alerts that could not be delivered by any remote channel
# are written as JSON (file fallback). Retry only helps transient failures;
# misconfiguration is surfaced via /api/system/notifications/health.
NOTIFY_RETRIES = max(0, int(os.environ.get("BARAQ_NOTIFY_RETRIES", "2")))
NOTIFY_FALLBACK_DIR = os.environ.get(
    "BARAQ_NOTIFY_FALLBACK_DIR",
    str(Path(os.environ.get("BARAQ_LOGS_DIR", "logs")).resolve() / "undelivered"),
)
# Prometheus scrape without auth: only when explicitly enabled; the
# authenticated /api/system/metrics endpoint is always available.
METRICS_PUBLIC = os.environ.get("BARAQ_METRICS_PUBLIC", "0").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# --------------------------------------------------------------------------
# Data quality / auto-fix corrupted event data
# --------------------------------------------------------------------------
# Corruption detection + repair: events whose process/command-line fields
# are rendering debris (truncated to a bare letter, symbol or <3-char stub)
# are discarded before detection, so corrupted log data cannot generate
# false-positive alerts. Rates are computed over a sliding window.
DATA_QUALITY_WINDOW_MINUTES = max(
    1, int(os.environ.get("BARAQ_DATA_QUALITY_WINDOW_MINUTES", "10"))
)
#: Corruption rate (0..1) above which the status turns WARNING (monitor),
#: DEGRADED (repair recommended) and CRITICAL (auto-repair).
DATA_QUALITY_WARN_RATE = float(os.environ.get("BARAQ_DATA_QUALITY_WARN_RATE", "0.10"))
DATA_QUALITY_DEGRADED_RATE = float(
    os.environ.get("BARAQ_DATA_QUALITY_DEGRADED_RATE", "0.30")
)
DATA_QUALITY_CRITICAL_RATE = float(
    os.environ.get("BARAQ_DATA_QUALITY_CRITICAL_RATE", "0.50")
)
#: Auto-run the repair sequence (clear logs, restart EventLog service,
#: retrain ML) when the window corruption rate crosses CRITICAL.
DATA_QUALITY_AUTO_REPAIR = os.environ.get(
    "BARAQ_DATA_QUALITY_AUTO_REPAIR", "0"
).lower() in (
    "1",
    "true",
    "yes",
    "on",
)
#: Background monitor cadence and the minimum gap between repairs.
DATA_QUALITY_MONITOR_SECONDS = max(
    5, int(os.environ.get("BARAQ_DATA_QUALITY_MONITOR_SECONDS", "60"))
)
DATA_QUALITY_REPAIR_COOLDOWN_MINUTES = max(
    1, int(os.environ.get("BARAQ_DATA_QUALITY_REPAIR_COOLDOWN_MINUTES", "15"))
)

# --------------------------------------------------------------------------
# Single-instance guard
# --------------------------------------------------------------------------
# Acquire a DB-scoped advisory lock at startup. A second process pointed at
# the same database fails the acquisition and disables its scheduler (it
# keeps serving API reads) instead of double-running collection/detection.
SINGLE_INSTANCE = os.environ.get("BARAQ_SINGLE_INSTANCE", "1").lower() not in (
    "0",
    "false",
    "no",
    "off",
)

# --------------------------------------------------------------------------
# Multi-endpoint ingest
# --------------------------------------------------------------------------
# JSON map {"agent_key": "agent-id"} for POST /api/ingest. A development
# default is provided; override via BARAQ_AGENT_KEYS.
try:
    _env_agent_keys = json.loads(_secret("BARAQ_AGENT_KEYS", "{}") or "{}")
except (ValueError, TypeError):
    _env_agent_keys = {}
AGENT_KEYS: dict[str, str] = {
    **{str(k): str(v) for k, v in _env_agent_keys.items()},
}

#: Tenant attribution for remote agents: {"agent-id": "org-id"}. Agents
#: without an entry are treated as system/central telemetry (org ""), which
#: only global (admin) roles can read. Use stable org ids - e.g. the short
#: name of the university/faculty - so they survive renames.
try:
    _env_agent_orgs = json.loads(_secret("BARAQ_AGENT_ORGS", "{}") or "{}")
except (ValueError, TypeError):
    _env_agent_orgs = {}
AGENT_ORGS: dict[str, str] = {str(k): str(v) for k, v in _env_agent_orgs.items()}


def agent_org(agent_id: str) -> str:
    """Organization a reporting agent belongs to ("" = system/central)."""
    return AGENT_ORGS.get(agent_id, "")


# --------------------------------------------------------------------------
# Incremental / asynchronous detection
# --------------------------------------------------------------------------
# When ON, POST /api/ingest persists records and returns immediately; the
# 15 s scheduler runs the rules engine over new events (incremental cursor).
# This decouples ingest throughput from rules-engine cost and is the
# recommended mode for fleets above ~50 endpoints. When OFF (default), each
# ingest batch is detected synchronously before the response returns.
INGEST_ASYNC_DETECT = os.environ.get("BARAQ_INGEST_ASYNC_DETECT", "0").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# --------------------------------------------------------------------------
# AI assistant
# --------------------------------------------------------------------------
# When set, the assistant delegates to the BARAQ AI endpoint.
# Leave empty to use the fully local rule/TF-IDF engine (default).
AI_API_URL = os.environ.get("BARAQ_AI_API_URL", "https://integrate.api.nvidia.com/v1")
AI_API_KEY = _secret("BARAQ_AI_API_KEY", "")
AI_MODEL = os.environ.get("BARAQ_AI_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
#: External AI calls are OFF by default. Even when BARAQ_AI_API_URL is set,
#: the assistant only calls it when BARAQ_AI_EXTERNAL_ENABLED=1, preventing
#: decrypted alert evidence and conversation history from leaking to an
#: external provider by accident.
AI_EXTERNAL_ENABLED = os.environ.get("BARAQ_AI_EXTERNAL_ENABLED", "0").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# --------------------------------------------------------------------------
# Threat intelligence
# --------------------------------------------------------------------------
# Optional provider API keys. When empty, the local offline reputation feed
# (backend/threatintel/feeds.py) is used; lookups are cached in the database
# for THREAT_INTEL_CACHE_HOURS.
THREAT_INTEL_ENABLED = os.environ.get("BARAQ_THREAT_INTEL_ENABLED", "1") == "1"
THREAT_INTEL_ABUSEIPDB_KEY = _secret("BARAQ_ABUSEIPDB_KEY", "")
THREAT_INTEL_OTX_KEY = _secret("BARAQ_OTX_KEY", "")
THREAT_INTEL_VT_KEY = _secret("BARAQ_VT_KEY", "")
THREAT_INTEL_SHODAN_KEY = _secret("BARAQ_SHODAN_KEY", "")
THREAT_INTEL_GREYNOISE_KEY = _secret("BARAQ_GREYNOISE_KEY", "")
THREAT_INTEL_CENSYS_KEY = _secret("BARAQ_CENSYS_KEY", "")
THREAT_INTEL_ABUSECH_KEY = _secret("BARAQ_ABUSECH_KEY", "")
THREAT_INTEL_FINDIP_KEY = _secret("BARAQ_FINDIP_KEY", "")
THREAT_INTEL_CACHE_HOURS = int(os.environ.get("BARAQ_THREAT_INTEL_CACHE_HOURS", "24"))
THREAT_INTEL_TIMEOUT = float(os.environ.get("BARAQ_THREAT_INTEL_TIMEOUT", "8"))
# Threat-intel feed subscriptions (roadmap 4.3): a JSON list of feed sources
# ingested by ``backend.intel.feeds.refresh_feeds`` (scheduler + Celery
# ``baraq.intel_refresh``). Each entry:
#   {"name": "misp-prod", "type": "misp", "url": "https://misp.local",
#    "api_key": "...", "collection_id": ""}   # MISP attribute export
#   {"name": "taxii", "type": "taxii", "url": "https://taxii.local/",
#    "api_key": "...", "collection_id": "guid"}   # TAXII 2.1 collection
#   {"name": "stix-bundle", "type": "stix", "url": "https://host/bundle.json"}
#   {"name": "plainlist", "type": "csv", "url": "https://host/iocs.txt"}
# IOC matching uses the DB-cached records with confidence >=
# THREAT_INTEL_FEED_MIN_CONFIDENCE; each feed is capped at
# THREAT_INTEL_FEED_MAX_IOCS per refresh.
THREAT_INTEL_FEEDS = json.loads(os.environ.get("BARAQ_THREAT_INTEL_FEEDS", "[]"))
THREAT_INTEL_FEED_MAX_IOCS = int(
    os.environ.get("BARAQ_THREAT_INTEL_FEED_MAX_IOCS", "5000")
)
THREAT_INTEL_FEED_MIN_CONFIDENCE = float(
    os.environ.get("BARAQ_THREAT_INTEL_FEED_MIN_CONFIDENCE", "0.6")
)

# --------------------------------------------------------------------------
# Streaming pipeline (Kafka / Redis / Elasticsearch forwarding)
# --------------------------------------------------------------------------
# Optional outbound bus for normalized events and alerts. Each sink is
# independent: configure the URL of a sink you have running and the exporter
# enables it; unconfigured sinks stay dormant. Missing driver packages
# degrade gracefully (logged once, sink reported as "unavailable") so the
# platform keeps working on a stock install.
STREAM_ENABLED = os.environ.get("BARAQ_STREAM_ENABLED", "0").lower() in (
    "1",
    "true",
    "yes",
    "on",
    "kafka",
    "redis",
    "es",
    "all",
)
#: Kafka bootstrap servers (comma-separated host:port) and topic to publish.
KAFKA_BOOTSTRAP_SERVERS = os.environ.get("BARAQ_KAFKA_BOOTSTRAP", "")
KAFKA_TOPIC = os.environ.get("BARAQ_KAFKA_TOPIC", "baraq-events")
#: Redis URL (redis://host:6379) + stream key for Redis Streams / PubSub.
REDIS_URL = os.environ.get("BARAQ_REDIS_URL", "")
REDIS_STREAM = os.environ.get("BARAQ_REDIS_STREAM", "baraq:events")
#: Elasticsearch / OpenSearch base URL + index pattern (rolling daily suffix).
ELASTICSEARCH_URL = os.environ.get("BARAQ_ELASTICSEARCH_URL", "")
ELASTICSEARCH_INDEX = os.environ.get("BARAQ_ELASTICSEARCH_INDEX", "baraq-events")
ELASTICSEARCH_USERNAME = os.environ.get("BARAQ_ELASTICSEARCH_USERNAME", "")
ELASTICSEARCH_PASSWORD = _secret("BARAQ_ELASTICSEARCH_PASSWORD", "")
#: Batching / retry tuning for the outbound buffer.
STREAM_BATCH_SIZE = int(os.environ.get("BARAQ_STREAM_BATCH_SIZE", "25"))
STREAM_FLUSH_SECONDS = float(os.environ.get("BARAQ_STREAM_FLUSH_SECONDS", "5.0"))
STREAM_MAX_RETRIES = int(os.environ.get("BARAQ_STREAM_MAX_RETRIES", "2"))

# --------------------------------------------------------------------------
# Entity intelligence graph
# --------------------------------------------------------------------------
# The entity graph is exposed through a provider interface so the storage
# backend can be swapped: "postgres" (default - uses the existing database,
# no extra services) or "neo4j" (requires a running Neo4j server + the
# `neo4j` driver). "auto" tries Neo4j only when BARAQ_NEO4J_URI is set
# and falls back to Postgres.
GRAPH_PROVIDER = os.environ.get("BARAQ_GRAPH_PROVIDER", "postgres").lower()
NEO4J_URI = os.environ.get("BARAQ_NEO4J_URI", "")
NEO4J_USER = os.environ.get("BARAQ_NEO4J_USER", "neo4j")
NEO4J_PASSWORD = _secret("BARAQ_NEO4J_PASSWORD", "")
NEO4J_DATABASE = os.environ.get("BARAQ_NEO4J_DATABASE", "neo4j")
#: Cap on graph expansion (neighbours / node count) served to the UI.
GRAPH_MAX_NODES = int(os.environ.get("BARAQ_GRAPH_MAX_NODES", "250"))
#: Cap on edges served to the UI - unbounded edge lists are the main
#: cause of entity-graph lag on busy fleets.
GRAPH_MAX_EDGES = int(os.environ.get("BARAQ_GRAPH_MAX_EDGES", "300"))

# --------------------------------------------------------------------------
# SOAR safety (Phase 0.12)
# --------------------------------------------------------------------------
# During the v2 rebuild, automatic destructive response actions are DISABLED
# by default. When disabled, playbook/action execution records the action as
# SIMULATED and performs no real side effect. Set to "1" to re-enable only
# after the new detection engine is validated end-to-end.
SOAR_DESTRUCTIVE_ACTIONS_ENABLED = os.environ.get(
    "BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED", "0"
).lower() in ("1", "true", "yes", "on")
#: Actions classified as destructive / high-impact. Gated by the flag above.
DESTRUCTIVE_ACTIONS = frozenset(
    {"block_ip", "kill_process", "quarantine", "isolate", "disable_account"}
)


def _csv_lower(name: str, default: str) -> frozenset[str]:
    """Comma-separated env var -> lowercase frozenset."""
    raw = os.environ.get(name, default)
    return frozenset(v.strip().lower() for v in raw.split(",") if v.strip())


def _env_flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).lower() in ("1", "true", "yes", "on")


#: Response safety guards (protect the operator's own workstation).
#: With guards on (default), destructive actions refuse to: kill core
#: shell/agent/system processes, isolate the host that serves this console,
#: or disable the machine's own user accounts. These are exactly the
#: mistakes that lock an analyst out of their own SOC during a drill.
SOAR_SAFETY_GUARDS = _env_flag("BARAQ_SOAR_SAFETY_GUARDS", "1")
#: Processes that must never be terminated by a response action.
SOAR_PROTECTED_PROCESSES = _csv_lower(
    "BARAQ_SOAR_PROTECTED_PROCESSES",
    "powershell.exe,pwsh.exe,cmd.exe,conhost.exe,explorer.exe,"
    "python.exe,pythonw.exe,uvicorn.exe,agent.py,agent.ps1,baraq-agent,"
    "lsass.exe,csrss.exe,smss.exe,wininit.exe,winlogon.exe,services.exe,"
    "svchost.exe,system,registry",
)
#: Hosts that must never be isolated - the console is served from here.
SOAR_PROTECTED_HOSTS = _csv_lower(
    "BARAQ_SOAR_PROTECTED_HOSTS", socket.gethostname()
)
#: Local accounts that must never be disabled.
SOAR_PROTECTED_ACCOUNTS = _csv_lower(
    "BARAQ_SOAR_PROTECTED_ACCOUNTS",
    f"{getpass.getuser()},administrator,guest",
)
#: Deliberate live-fire drill switches - enable only in an isolated lab.
SOAR_ALLOW_SELF_ISOLATE = _env_flag("BARAQ_SOAR_ALLOW_SELF_ISOLATE")
SOAR_ALLOW_PROTECTED_ACTIONS = _env_flag("BARAQ_SOAR_ALLOW_PROTECTED_ACTIONS")

# --------------------------------------------------------------------------
# v2 telemetry (Phase 1)
# --------------------------------------------------------------------------
# The v2 pipeline is not live yet; the API is inert unless explicitly
# enabled. Development/evaluation environments may enable it; production
# must keep it off until Phase 1 validation completes.
TELEMETRY_V2_ENABLED = os.environ.get("BARAQ_TELEMETRY_V2", "1").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

#: Name of the v1 production database (Phase 0.7). The v2 workstream must
#: never write to it: this is enforced here and in the ingestion pipeline.
PRODUCTION_DB_NAME = "sentinel"

#: Allow v2 engines to run against the production database (local dev only).
#: The default is False - the v2 workstream must never write to the production
#: database unless the operator explicitly opts in.
V2_ENGINES_ALLOW_PROD = os.environ.get("BARAQ_V2_ENGINES_ALLOW_PROD", "0").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

from sqlalchemy.engine import make_url as _make_url

_DB_NAME = _make_url(DATABASE_URL).database or ""

_V2_PROD_GATE = not V2_ENGINES_ALLOW_PROD and (_DB_NAME == PRODUCTION_DB_NAME)

# Isolation gate (Phase 0.7): the v2 pipeline stays disabled whenever the
# configured database is the production DB - even if BARAQ_ENV is unset and
# defaults to "development". BARAQ_ENV alone is not the boundary; the
# production database is.
if _V2_PROD_GATE:
    TELEMETRY_V2_ENABLED = False

# --------------------------------------------------------------------------
# v2 alert management (Phase 3)
# --------------------------------------------------------------------------
# Same lifecycle as the v2 telemetry/detection surfaces: inert unless
# explicitly enabled, and always inert on the production database.
ALERTS_V2_ENABLED = os.environ.get("BARAQ_ALERTS_V2", "1").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
if _V2_PROD_GATE:
    ALERTS_V2_ENABLED = False

#: Dedup window per detector (spec 3.9): a new detection merges into an
#: existing alert when its fingerprint matches and the alert's last_seen is
#: within this many minutes. Initial defaults, stored in configuration.
ALERT_DEDUP_WINDOW_MINUTES = {
    "D001": 15,
    "D002": 15,
    "D003": 10,
    "D004": 10,
    "D005": 5,
}
ALERT_DEDUP_WINDOW_DEFAULT_MINUTES = 10

#: Severity-based SLA definitions (spec 3.24): initial operational defaults,
#: not universal SOC standards. Age buckets only become "overdue" once an
#: explicit SLA policy is consumed by the UI.
ALERT_SLA_MINUTES = {"critical": 15, "high": 30, "medium": 120, "low": 480}

#: Minimum number of labeled alerts before a false-positive rate is reported
#: (spec 3.15): never present FPR from zero or tiny feedback samples.
ALERT_MIN_LABELED_FOR_FPR = 10

#: Maximum lifetime of a suppression rule in days (spec 3.25/3.26): permanent
#: silent suppression is not allowed - every rule must expire within a
#: bounded, auditable horizon.
ALERT_SUPPRESSION_MAX_DAYS = int(
    os.environ.get("BARAQ_ALERT_SUPPRESSION_MAX_DAYS", "90")
)

# --------------------------------------------------------------------------
# v2 behavioral aggregation (Phase 4)
# --------------------------------------------------------------------------
# Same lifecycle as the v2 telemetry/detection/alert surfaces: inert unless
# explicitly enabled, and always inert on the production database.
BEHAVIOR_GROUPS_ENABLED = os.environ.get("BARAQ_BEHAVIOR_GROUPS", "1").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
if _V2_PROD_GATE:
    BEHAVIOR_GROUPS_ENABLED = False

#: Detector -> behavior family (spec 4.9, 4.49): grouping is behavioral, not
#: title- or MITRE-based. D001 (external RDP) and D002 (brute force) share
#: the authentication family - the spec's own example groups External RDP +
#: Failed Logon + Successful Logon into one "Remote Authentication Activity"
#: group. D003/D004 are execution, D005 is ransomware-like encryption.
#: Unknown detectors fail closed into their own "unknown" family.
DETECTOR_BEHAVIOR_FAMILIES = {
    "D001": "authentication",
    "D002": "authentication",
    "D003": "execution",
    "D004": "execution",
    "D005": "encryption",
}
BEHAVIOR_FAMILY_DEFAULT = "unknown"

#: Aggregation window per behavior family in minutes (spec 4.13): initial
#: defaults - standard 30, high-risk behavior 15, ransomware-like 10,
#: authentication 15. Configurable, never hardcoded in the grouping engine.
AGGREGATION_WINDOWS_MINUTES = {
    "authentication": 15,
    "execution": 30,
    "encryption": 10,
    "unknown": 30,
}
AGGREGATION_WINDOW_DEFAULT_MINUTES = 30

#: Group inactivity lifecycle (spec 4.15): a group becomes QUIET this many
#: minutes after its last alert, and CLOSED after the close timeout.
AGGREGATION_QUIET_AFTER_MINUTES = 30
AGGREGATION_CLOSE_AFTER_MINUTES = 60

#: Minimum contextual relationships required to join a group (spec 4.19):
#: two. Fingerprint equality guarantees host + user + source + family
#: shared by construction, which always exceeds this floor.
AGGREGATION_MIN_RELATIONSHIPS = 2

#: Membership score weights (spec 4.18): host +0.40, user +0.25, source
#: +0.20, time proximity +0.15 = 1.00. A grouping score, never a risk score.
AGGREGATION_MEMBERSHIP_WEIGHTS = {
    "host": 0.40,
    "user": 0.25,
    "source": 0.20,
    "time": 0.15,
}

# --------------------------------------------------------------------------
# v2 behavioral correlation (Phase 5)
# --------------------------------------------------------------------------
# Same lifecycle as every other v2 surface: inert unless explicitly enabled,
# always inert on the production database.
CORRELATION_ENABLED = os.environ.get("BARAQ_CORRELATION", "1").lower() in (
    "1",
    "true",
    "yes",
    "on",
)
if _V2_PROD_GATE:
    CORRELATION_ENABLED = False

#: Correlation windows in minutes (spec 5.9): configurable, never hardcoded
#: in the rules. A finding is only built when every consecutive member pair
#: falls inside the sequence window.
CORRELATION_WINDOWS_MINUTES = {
    "authentication_to_execution": 30,
    "execution_to_privilege": 60,
    "host_to_host_lateral_movement": 60,
    "multi_stage": 120,
}
CORRELATION_WINDOW_DEFAULT_MINUTES = 120

#: Correlation lifecycle (spec 5.31): QUIET after this many minutes without
#: a new member group, CLOSED after the close timeout.
CORRELATION_QUIET_AFTER_MINUTES = 120
CORRELATION_CLOSE_AFTER_MINUTES = 240

#: Minimum contextual relationships required to build an edge between two
#: groups (spec 5.22): two - e.g. same host + temporal proximity. A single
#: weak attribute (same MITRE, same host, same source alone) never suffices.
CORRELATION_MIN_RELATIONSHIPS = 2

#: Edge strength weights (spec 5.21): deterministic correlation strength,
#: never a risk score. A pair of groups may share several factors; the edge
#: strength is the sum of the factors it actually shares, capped at 1.000.
CORRELATION_EDGE_WEIGHTS = {
    "host": 0.30,
    "user": 0.25,
    "source": 0.20,
    "time": 0.15,
    "technique": 0.10,
}

#: Confidence formula (spec 5.23): 0.40 + 0.10*(shared factors - 2) + 0.10
#: when a tactic progression exists + 0.05 when the sequence spans >= 3
#: groups, clamped to [0.20, 0.90]. Deterministic, bounded, never summed
#: from group confidences (spec 5.24).
CORRELATION_CONFIDENCE_BASE = 0.40
CORRELATION_CONFIDENCE_PER_FACTOR = 0.10
CORRELATION_CONFIDENCE_PROGRESSION_BONUS = 0.10
CORRELATION_CONFIDENCE_SEQUENCE_BONUS = 0.05
CORRELATION_CONFIDENCE_LATERAL_BONUS = 0.03
CORRELATION_CONFIDENCE_MIN = 0.20
CORRELATION_CONFIDENCE_MAX = 0.90

#: Performance guard (spec 5.75): candidate generation is partitioned by
#: entity + time (no O(n^2) sweep). A candidate pair is only examined when
#: the groups share at least one of these indexed keys.
CORRELATION_ENTITY_KEYS = ("host", "user", "source")

# --------------------------------------------------------------------------
# v2 entity risk intelligence (Phase 6)
# --------------------------------------------------------------------------
# Same lifecycle as every other v2 surface: inert unless explicitly enabled,
# always inert on the production database.
RISK_ENABLED = os.environ.get("BARAQ_RISK", "1").lower() in ("1", "true", "yes", "on")
if _V2_PROD_GATE:
    RISK_ENABLED = False

#: Risk model version (spec 6.39): any change to weights/thresholds/decay
#: bumps this so historical calculations stay attributable.
RISK_MODEL_VERSION = "1.0.0"

#: Score -> severity thresholds (spec 6.8): deterministic, configurable.
#: Every score-to-severity transition goes through this map only.
RISK_THRESHOLDS = {
    "minimal": 0,
    "low": 20,
    "medium": 40,
    "high": 60,
    "critical": 80,
}

#: Factor base weights (spec 6.11, 6.40): one factor per source with
#: provenance; repetition scales repeated identical sources via the curve.
RISK_FACTOR_WEIGHTS = {
    "RF001_EXTERNAL_ACCESS": 12,
    "RF002_CREDENTIAL_ACCESS": 14,
    "RF003_LATERAL_MOVEMENT": 18,
    "RF004_PRIVILEGE_ACTIVITY": 10,
    "RF005_EXECUTION": 8,
    "RF006_MULTI_STAGE_CORRELATION": 10,
    "RF007_REPETITION": 0,
    "RF008_RECENCY": 8,
    "RF009_ALERT_SEVERITY": 6,
    "RF010_BEHAVIOR_GROUP": 10,
    "RF011_PERSISTENCE": 10,
    "RF012_DEFENSE_EVASION": 8,
    "RF013_ENTITY_SPREAD": 8,
    "RF014_SOURCE_REPUTATION": 0,
}

#: Per-alert severity tier contribution (RF009), applied once per entity per
#: tier - never per alert (anti risk explosion, spec 6.12).
RISK_ALERT_SEVERITY_CONTRIBUTIONS = {
    "critical": 8,
    "high": 6,
    "medium": 3,
    "low": 1,
}

#: Maximum any single factor may contribute (spec 6.11).
RISK_MAX_FACTOR_CONTRIBUTION = 25

#: Repetition curve (spec 6.13): first occurrence of identical evidence
#: contributes its full factor weight; each subsequent occurrence adds a
#: diminishing amount (15, 8, 4, 2, ...). Configurable.
RISK_REPETITION_CURVE = (15.0, 8.0, 4.0, 2.0)

#: Deterministic exponential decay (spec 6.19): effective contribution =
#: value * 0.5^(age_hours / half_life).
RISK_DECAY_HALF_LIFE_HOURS = 24

#: Recency bonus (RF008): applied once per entity when its most recent
#: evidence is younger than this window.
RISK_RECENCY_BONUS_HOURS = 1

#: State is STALE when the last calculation is older than this (spec 6.76).
RISK_STALE_AFTER_MINUTES = 60

#: Trend (spec 6.24): RISING/FALLING when the latest snapshot differs from
#: the previous by at least this many points; descriptive only.
RISK_TREND_DELTA = 3
RISK_TREND_WINDOW_MINUTES = 90

#: Contextual propagation (spec 6.27): bounded per relationship, with
#: evidence, never risk copying. Contribution expires after the window.
RISK_PROPAGATION_WEIGHTS = {
    "user_to_host": 8,
    "host_to_user": 8,
    "source_to_host": 6,
    "user_to_source": 6,
    "host_to_source": 6,
}
RISK_PROPAGATION_EXPIRES_HOURS = 72

#: Factor lifetime: factors expire (contribution = 0) after this many hours
#: unless refreshed by new evidence (spec 6.21). Audit history remains.
RISK_FACTOR_EXPIRES_HOURS = 168

#: Risk confidence (spec 6.4): share of the current score resting on DIRECT
#: evidence vs contextual propagation; 1.0 when no context exists.
RISK_CONFIDENCE_MIN = 0.0
RISK_CONFIDENCE_MAX = 1.0

# Run the production gate last: it references many of the flags above and
# must only fire after every constant is bound.
_assert_production_safe()
