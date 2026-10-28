"""BARAQ remote agent - collect and ship telemetry to a central server.

Run on any Windows host (including the server itself) to form a 2-3 host
fleet:

    python scripts/agent.py --server https://central:8443 --key <agent-key> --interval 15
    python scripts/agent.py --server https://central:8443 --key <agent-key> --tls-ca certs/baraq.crt

HTTPS is the standard transport for fleet deployments: the server's
self-signed certificate (certs/baraq.crt) can be pinned on the agent with
``--tls-ca`` so connections are verified end-to-end. ``--no-verify`` exists
for lab use only and logs a warning. Plain ``http://`` works for local
single-host setups.

The agent runs the same collector set as the server, stamps every record
with the local hostname, and POSTs it to ``POST /api/ingest``. The server
validates the ``X-Agent-Key`` header, attributes the records to the agent,
and runs the full detection pipeline centrally.

On non-Windows hosts (where the Windows collectors cannot import) the agent
falls back to the minimal Linux collectors in ``scripts/linux_collect.py``
(auth.log logon events, network connections, new processes).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s"
)
logger = logging.getLogger("baraq.agent")

AGENT_CONFIG_DIR = Path(
    os.environ.get(
        "BARAQ_AGENT_CONFIG_DIR",
        str(Path.home() / "AppData" / "Local" / "BARAQAgent"),
    )
)
AGENT_CONFIG_FILE = AGENT_CONFIG_DIR / "agent.config.json"
AGENT_TASK_NAME = "BARAQ Agent"
#: Fleet auto-update (roadmap 3.4): reported on every ingest so the fleet
#: view can spot stale agents; update_agent commands target this version.
AGENT_VERSION = "2.0.0"

#: Network budgets. The ingest POST runs the full detection pipeline on the
#: server, so a cold or loaded server needs far longer than a command poll.
#: Too short a timeout here is worse than a slow agent: the client aborts and
#: resubmits the same batch, producing duplicate events.
INGEST_TIMEOUT_SECONDS = int(os.environ.get("BARAQ_AGENT_INGEST_TIMEOUT", "300"))
POLL_TIMEOUT_SECONDS = int(os.environ.get("BARAQ_AGENT_POLL_TIMEOUT", "30"))

_VERSION_RE = re.compile(r"^\d{1,6}(\.\d{1,6}){0,3}(-[0-9A-Za-z][0-9A-Za-z._-]{0,31})?$")
_PROCESS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$")
_SHELL_META = set("'\"`$;|&<>\n\r\t*?()[]{}^%!")


# ── Local safety guards ───────────────────────────────────────────────────
# Defense in depth: even if the server's protection lists are bypassed or
# misconfigured, the agent refuses to kill its own shell/agent/system
# processes or disable this machine's own accounts. Same env overrides as
# the server so an intentional lab drill can open both at once.

def _env_csv(name: str, default: str) -> frozenset[str]:
    raw = os.environ.get(name, default)
    return frozenset(v.strip().lower() for v in raw.split(",") if v.strip())


def _env_flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).lower() in ("1", "true", "yes", "on")


_PROTECTED_PROCESSES = _env_csv(
    "BARAQ_SOAR_PROTECTED_PROCESSES",
    "powershell.exe,pwsh.exe,cmd.exe,conhost.exe,explorer.exe,"
    "python.exe,pythonw.exe,uvicorn.exe,agent.py,agent.ps1,baraq-agent,"
    "lsass.exe,csrss.exe,smss.exe,wininit.exe,winlogon.exe,services.exe,"
    "svchost.exe,system,registry",
)
try:
    import getpass as _getpass

    _SELF_USER = _getpass.getuser()
except Exception:  # pragma: no cover - service accounts without a profile
    _SELF_USER = ""
_PROTECTED_ACCOUNTS = _env_csv(
    "BARAQ_SOAR_PROTECTED_ACCOUNTS",
    ",".join(u for u in (_SELF_USER, "administrator", "guest") if u),
)


def _guards_enabled() -> bool:
    """Guards off only when BARAQ_SOAR_SAFETY_GUARDS=0 or the drill
    override BARAQ_SOAR_ALLOW_PROTECTED_ACTIONS=1 is set."""
    if not _env_flag("BARAQ_SOAR_SAFETY_GUARDS", "1"):
        return False
    return not _env_flag("BARAQ_SOAR_ALLOW_PROTECTED_ACTIONS")


def _image_name_for_pid(pid: str) -> str | None:
    """Resolve a PID to its image name (e.g. powershell.exe), best effort."""
    tasklist = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "tasklist.exe"
    )
    try:
        out, code = _run([tasklist, "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"])
    except Exception:
        return None
    if code != 0 or '"' not in out:
        return None
    name = out.split('"')[1].strip()
    return name or None


class UnsafeCommand(ValueError):
    """A queued command target failed local validation."""


def validate_target(action: str, target: str) -> str:
    """Validate server-provided command data before using it locally."""
    target = (target or "").strip()
    if action == "escalate":
        return target
    if not target:
        raise UnsafeCommand(f"{action} requires a target")
    if action in ("block_ip", "unblock_ip"):
        try:
            return str(ipaddress.ip_address(target))
        except ValueError:
            raise UnsafeCommand(f"{action} requires a valid IP address") from None
    if action == "kill_process":
        if not _PROCESS_RE.match(target):
            raise UnsafeCommand("kill_process target must be a process name or PID")
        if _guards_enabled():
            name = target
            if target.isdigit():
                name = _image_name_for_pid(target) or ""
                if not name:
                    return target  # unresolvable PID: nothing to kill anyway
            name = os.path.basename(name).lower()
            exe = name if name.endswith(".exe") else f"{name}.exe"
            if name in _PROTECTED_PROCESSES or exe in _PROTECTED_PROCESSES:
                raise UnsafeCommand(
                    f"kill_process refused: '{target}' is a protected core process "
                    f"(shell/agent/system)"
                )
        return target
    if action == "quarantine":
        if len(target) > 400 or _SHELL_META & set(target):
            raise UnsafeCommand("quarantine target contains forbidden characters")
        if not re.match(r"^([A-Za-z]:[\\/]|\\\\|/)", target):
            raise UnsafeCommand("quarantine target must be an absolute path")
        if ".." in re.split(r"[\\/]+", target):
            raise UnsafeCommand("quarantine target must not traverse directories")
        return target
    if action == "isolate":
        if not _HOSTNAME_RE.match(target):
            raise UnsafeCommand("isolate target must be a hostname")
        return target
    if action == "disable_account":
        if not _ACCOUNT_RE.match(target):
            raise UnsafeCommand("disable_account target must be an account name")
        if (
            _guards_enabled()
            and target.lower() in _PROTECTED_ACCOUNTS
        ):
            raise UnsafeCommand(
                f"disable_account refused: '{target}' is a protected local "
                f"account (operator/admin)"
            )
        return target
    if action == "update_agent":
        if not _VERSION_RE.match(target):
            raise UnsafeCommand("update_agent target must be a version, e.g. 2.1.0")
        return target
    raise UnsafeCommand(f"unsupported action: {action}")


def _os_banner() -> str:
    """Short OS banner for the fleet view (e.g. 'Windows 10.0.19045')."""
    try:
        import platform

        if sys.platform.startswith("win"):
            return platform.platform(terse=True)
        return platform.platform()
    except Exception:
        return sys.platform


def make_tls_context(
    tls_ca: str | None = None, no_verify: bool = False
) -> ssl.SSLContext | None:
    """Build the SSL context used for https:// server URLs.

    * ``tls_ca`` - PEM file to pin (the central server's self-signed cert);
      verification then succeeds without touching the system store.
    * ``no_verify`` - lab-only: accept any certificate (logs a warning).
    * neither - the default system store is used (imported CAs only).
    Returns ``None`` for plain http:// URLs (no TLS involved).
    """
    if no_verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning(
            "TLS verification disabled (--no-verify) - use only in isolated labs"
        )
        return ctx
    if tls_ca:
        ctx = ssl.create_default_context(cafile=tls_ca)
        logger.info("Pinning central TLS certificate: %s", tls_ca)
        return ctx
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, "redirects disabled", headers, fp)


def _validate_server_url(server: str) -> str:
    parsed = urllib.parse.urlparse(server)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"unsupported server URL: {server!r}")
    if parsed.username or parsed.password:
        raise ValueError("server URL must not embed credentials")
    return server


def _request(
    base: str,
    path: str,
    key: str,
    payload: dict | None = None,
    method: str = "GET",
    tls_ca: str | None = None,
    no_verify: bool = False,
) -> dict:
    url = _validate_server_url(base.rstrip("/")) + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json", "X-Agent-Key": key}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    context = make_tls_context(tls_ca, no_verify)
    # The TLS context must be bound to the HTTPS handler - OpenerDirector.open()
    # has no `context` parameter (only urlopen() does), so passing it there made
    # every single agent request fail with a TypeError and the agent silently
    # collected nothing.
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=context)
    )
    # Ingest triggers the whole detection pipeline server-side. A cold server
    # (first batch, rule/sigma load, ML scoring) regularly needs more than 30s,
    # and a client-side abort there makes the agent resubmit the same batch -
    # duplicate events. Command polls stay short so the loop stays responsive.
    timeout = INGEST_TIMEOUT_SECONDS if method == "POST" else POLL_TIMEOUT_SECONDS
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read(8 * 1024 * 1024).decode("utf-8"))


def _run(cmd: list[str], env: dict | None = None) -> tuple[str, int]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return (proc.stdout + proc.stderr).strip(), proc.returncode


def _run_powershell(script: str, values: dict[str, str]) -> tuple[str, int]:
    env = {**os.environ, **{f"BARAQ_ARG_{key}": value for key, value in values.items()}}
    return _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        env=env,
    )


def execute_command(cmd: dict) -> dict:
    """Execute one remote command locally; returns the result report dict."""
    action = str(cmd.get("action", ""))
    try:
        target = validate_target(action, str(cmd.get("target", "")))
    except UnsafeCommand as exc:
        logger.error("Refusing %s command: %s", action, exc)
        return {"status": "failed", "detail": str(exc)}

    system32 = Path(os.environ.get("SystemDrive", "C:") + "\\Windows\\System32")

    def system_binary(name: str) -> str:
        return str(system32 / f"{name}.exe")

    if action == "block_ip":
        success = False
        detail = ""
        for direction in ("in", "out"):
            detail, code = _run(
                [
                    system_binary("netsh"),
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name=BARAQ Block {target} {direction}",
                    f"dir={direction}",
                    "action=block",
                    f"remoteip={target}",
                    "enable=yes",
                ]
            )
            success = success or code == 0
        return {"status": "success" if success else "failed", "detail": detail or "ok"}

    if action == "unblock_ip":
        # Rule names are exact matches for netsh delete, and the two agents
        # name their block rules differently (this agent: "BARAQ Block <ip>
        # <dir>"; agent.ps1: "BARAQ-SOAR-<DIR>-<ip>"). Delete both families
        # so a block created by either agent type can be undone from here.
        dashed = target.replace(".", "-")
        names = (
            f"BARAQ Block {target} in",
            f"BARAQ Block {target} out",
            f"BARAQ-SOAR-IN-{dashed}",
            f"BARAQ-SOAR-OUT-{dashed}",
        )
        removed = 0
        detail = ""
        for name in names:
            out, code = _run(
                [
                    system_binary("netsh"),
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    f"name={name}",
                ]
            )
            detail = detail or out
            if code == 0:
                removed += 1
        if removed == 0:
            return {
                "status": "failed",
                "detail": f"no BARAQ block rules found for {target}",
            }
        return {"status": "success", "detail": f"unblocked {target} ({removed} rule(s) removed)"}

    if action == "kill_process":
        args = ["/F", "/PID", target] if target.isdigit() else ["/F", "/IM", target]
        out, code = _run([system_binary("taskkill"), *args])
        lowered = out.lower()
        if code != 0 and ("not found" in lowered or "no tasks" in lowered):
            return {"status": "success", "detail": f"process {target} was not running"}
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}

    if action == "quarantine":
        drive = os.environ.get("SystemDrive", "C:")
        quarantine = os.path.join(f"{drive}\\", "BARAQ-Quarantine")
        if not os.path.exists(target):
            return {"status": "failed", "detail": f"path not found: {target}"}
        out, code = _run_powershell(
            "if (-not (Test-Path -LiteralPath $env:BARAQ_ARG_DEST)) "
            "{ New-Item -ItemType Directory -Path $env:BARAQ_ARG_DEST -Force | Out-Null }; "
            "Move-Item -LiteralPath $env:BARAQ_ARG_SRC -Destination $env:BARAQ_ARG_DEST -Force",
            {"SRC": target, "DEST": quarantine},
        )
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}

    if action == "isolate":
        out, code = _run_powershell(
            "New-NetFirewallRule -DisplayName $env:BARAQ_ARG_NAME -Direction Inbound "
            "-Action Block -Profile Any | Out-Null; "
            "New-NetFirewallRule -DisplayName ($env:BARAQ_ARG_NAME + ' Out') "
            "-Direction Outbound -Action Block -Profile Any | Out-Null",
            {"NAME": f"BARAQ Isolate {target}"},
        )
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}

    if action == "disable_account":
        out, code = _run_powershell(
            "Disable-LocalUser -Name $env:BARAQ_ARG_NAME -ErrorAction Stop",
            {"NAME": target},
        )
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}

    if action == "escalate":
        logger.warning(
            "Operator escalated agent %s - manual review required", cmd.get("agent_id")
        )
        return {"status": "success", "detail": "Acknowledged by operator"}

    if action == "update_agent":
        updater = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "agent_updater.ps1"
        )
        if not os.path.exists(updater):
            return {
                "status": "failed",
                "detail": f"updater not configured for target version {target}",
            }
        args = [
            system_binary("powershell"),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            updater,
            "-Version",
            target,
        ]
        expected_hash = str(cmd.get("sha256") or "")
        if expected_hash:
            args.extend(["-ExpectedSha256", expected_hash])
        out, code = _run(args)
        return {
            "status": "success" if code == 0 else "failed",
            "detail": out or f"updated to {target}",
        }

    return {"status": "failed", "detail": f"Unknown action: {action}"}


class CollectorsUnavailable(RuntimeError):
    """No collector stack could be loaded on this host."""


def collect() -> list[dict]:
    """Collect telemetry with the full Windows collector stack.

    Requires the ``backend`` package next to the agent (and pywin32 on
    Windows). When it is missing we raise instead of returning an empty list:
    an agent that quietly reports nothing looks identical to a healthy machine
    with nothing to report, which is the worst possible failure mode for a SOC.
    """
    from backend.collectors import CollectorManager

    host = socket.gethostname()
    records = []
    for record in CollectorManager().collect():
        record["host"] = host
        records.append(record)
    return records


def collect_fallback() -> list[dict]:
    """Non-Windows hosts: use the minimal Linux collectors."""
    host = socket.gethostname()
    records = []
    try:
        from scripts.linux_collect import collect as linux_collect

        for record in linux_collect():
            record["host"] = host
            records.append(record)
    except ImportError as exc:
        raise CollectorsUnavailable(
            f"no collector stack on this host: {exc}. The full Python agent "
            f"needs the 'backend' package and 'scripts/linux_collect.py' next "
            f"to it, or use the self-contained scripts/agent.ps1 instead."
        ) from exc
    return records


def load_config(path: Path | None = None) -> dict:
    """Merge agent.config.json with the environment; CLI flags win later."""
    path = path or AGENT_CONFIG_FILE
    cfg: dict = {}
    try:
        cfg = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError:
        pass
    except ValueError as exc:
        logger.warning("Ignoring malformed agent config %s: %s", path, exc)
    for key in ("interval",):
        try:
            cfg[key] = int(cfg[key])
        except (KeyError, TypeError, ValueError):
            cfg.setdefault(key, 15)
    return cfg


def save_config(values: dict, path: Path | None = None) -> Path:
    path = path or AGENT_CONFIG_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values, indent=2), encoding="utf-8")
    return path


def _agent_launcher_python() -> tuple[str, list[str]]:
    """Return (launcher target, args) that survive reboots for the current install."""
    if getattr(sys, "frozen", False):
        return sys.executable, ["--config", str(AGENT_CONFIG_FILE)]
    return sys.executable, [
        "-u",
        str(Path(__file__).resolve()),
        "--config",
        str(AGENT_CONFIG_FILE),
    ]


def install_task(values: dict) -> None:
    """Register the agent as a logon scheduled task (no admin rights needed)."""
    launcher = AGENT_CONFIG_DIR / "agent_launcher.ps1"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    target, args = _agent_launcher_python()
    quoted = "', '".join(arg.replace("'", "''") for arg in args)
    launcher.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"Start-Process -FilePath '{target}' -ArgumentList @('{quoted}') -WindowStyle Hidden\n",
        encoding="utf-8",
    )
    quote = subprocess.list2cmdline
    cmd = (
        "schtasks",
        "/Create",
        "/F",
        "/TN",
        AGENT_TASK_NAME,
        "/TR",
        quote(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-File",
                str(launcher),
            ],
        ),
        "/SC",
        "ONLOGON",
        "/RL",
        "LIMITED",
    )
    out, code = _run(list(cmd))
    if code != 0:
        raise RuntimeError(f"Could not register scheduled task: {out}")
    _run(["schtasks", "/Run", "/TN", AGENT_TASK_NAME])
    logger.info(
        "Agent installed: %s -> %s (task '%s', starts at every logon)",
        target,
        values.get("server"),
        AGENT_TASK_NAME,
    )


def uninstall_task(purge: bool) -> None:
    out, code = _run(["schtasks", "/Delete", "/F", "/TN", AGENT_TASK_NAME])
    if code == 0:
        logger.info("Scheduled task '%s' removed", AGENT_TASK_NAME)
    else:
        logger.info("No task to remove (%s)", out.strip() or "not registered")
    if purge:
        import shutil

        shutil.rmtree(AGENT_CONFIG_DIR, ignore_errors=True)
        AGENT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("Config directory purged: %s", AGENT_CONFIG_DIR)


def configure_logging(log_file: str | None) -> None:
    """Send INFO+ output to a file too (invisible when launched windowed)."""
    if not log_file:
        return
    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")
    )
    logger.addHandler(handler)


def main() -> None:
    os.environ.setdefault("BARAQ_SKIP_SECRET_GEN", "1")
    os.environ.setdefault(
        "BARAQ_DATABASE_URL",
        "postgresql+psycopg://postgres@127.0.0.1:55432/baraq",
    )
    parser = argparse.ArgumentParser(description="BARAQ remote telemetry agent")
    parser.add_argument(
        "--server", default=None, help="Central BARAQ API (HTTPS standard, port 8443)"
    )
    parser.add_argument("--key", default=None, help="Agent key (X-Agent-Key)")
    parser.add_argument(
        "--interval", type=int, default=None, help="Collection interval (seconds)"
    )
    parser.add_argument(
        "--tls-ca",
        default=None,
        help="PEM cert file of the central server (certs/baraq.crt) to pin",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="LAB ONLY: skip TLS certificate verification",
    )
    parser.add_argument(
        "--config",
        default=str(AGENT_CONFIG_FILE),
        help="JSON config file (server/key/interval/tls-ca)",
    )
    parser.add_argument(
        "--log",
        default=str(AGENT_CONFIG_DIR / "agent.log"),
        help="Append log output to this file",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Register as an autostart task and start agent now",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove the autostart task (--purge deletes the config)",
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        help="With --uninstall: also delete the config directory",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Log debug-level detail (collector failures, batches)",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    configure_logging(args.log if args.log else None)

    if args.uninstall:
        uninstall_task(args.purge)
        return

    cfg = load_config(Path(args.config))
    server = args.server or cfg.get("server") or "https://127.0.0.1:8443"
    key = args.key or cfg.get("key") or "baraq-agent-dev"
    interval = args.interval or cfg.get("interval") or 15
    tls_ca = args.tls_ca or cfg.get("tls_ca")
    no_verify = args.no_verify or bool(cfg.get("no_verify"))
    parsed_server = urllib.parse.urlparse(server)
    if parsed_server.scheme not in ("http", "https") or not parsed_server.hostname:
        parser.error(f"invalid server URL: {server}")
    is_loopback = parsed_server.hostname in ("127.0.0.1", "localhost", "::1")
    if parsed_server.scheme == "http" and not is_loopback:
        parser.error("HTTPS is required for non-loopback BARAQ servers")
    if no_verify and not is_loopback:
        parser.error("TLS verification cannot be disabled for a non-loopback server")

    if args.install:
        values = {
            "server": server,
            "key": key,
            "interval": interval,
            "tls_ca": tls_ca or "",
            "no_verify": no_verify,
            "log": args.log,
        }
        save_config(values, Path(args.config))
        install_task(values)
        return

    host = socket.gethostname()
    logger.info("BARAQ agent starting (host=%s, server=%s)", host, server)
    while True:
        try:
            try:
                pending = _request(
                    server,
                    "/api/commands/pending",
                    key,
                    tls_ca=tls_ca,
                    no_verify=no_verify,
                )
                for cmd in pending.get("items", []):
                    report = execute_command(cmd)
                    try:
                        _request(
                            server,
                            f"/api/commands/{cmd['id']}/result",
                            key,
                            report,
                            method="POST",
                            tls_ca=tls_ca,
                            no_verify=no_verify,
                        )
                        logger.info(
                            "Command #%s (%s %s) -> %s",
                            cmd["id"],
                            cmd["action"],
                            cmd["target"],
                            report["status"],
                        )
                    except Exception as exc:
                        logger.warning(
                            "Failed to report command #%s: %s", cmd.get("id"), exc
                        )
            except Exception as exc:
                logger.warning("Command poll failed: %s", exc)

            records = []
            try:
                records = collect()
            except CollectorsUnavailable as exc:
                logger.debug("Windows collectors unavailable (%s); Linux fallback", exc)
                records = collect_fallback()
            except Exception as exc:
                logger.debug("Windows collectors failed (%s); Linux fallback", exc)
                records = collect_fallback()
            if not records:
                # Never let a misconfigured agent look like a quiet machine.
                logger.error(
                    "No telemetry collected on %s - this agent is reporting "
                    "nothing. Check that the collector stack is installed (full "
                    "Python agent) or deploy scripts/agent.ps1.",
                    host,
                )
            if records:
                result = _request(
                    server,
                    "/api/ingest",
                    key,
                    {
                        "records": records,
                        "host": host,
                        "agent_version": AGENT_VERSION,
                        "os_info": _os_banner(),
                    },
                    method="POST",
                    tls_ca=tls_ca,
                    no_verify=no_verify,
                )
                logger.info(
                    "Shipped %d records -> %s alerts",
                    result.get("collected", 0),
                    result.get("alerts_created", 0),
                )
            else:
                logger.debug("No records collected")
        except Exception as exc:
            logger.warning("Agent cycle failed: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
