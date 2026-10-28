#!/usr/bin/env python3
"""Parse BOTSv1 Sysmon JSON into the labeled network benchmark frame.

The BOTSv1 export is a gzip of one JSON object per line, with the Sysmon
fields under the ``result`` key.  This parser reproduces the labels and
host/time windows used by the BARAQ benchmark:

* Campaign A: every network event to the Joomla C2 IP
  ``108.161.187.134``, plus the three ``3791.exe`` / ``nslookup.exe``
  events on ``we1149srv`` during the A window.
* Campaign B: every network event from the Cerber ``osk.exe`` payload, plus
  the two ``iexplore.exe`` events at the exact 2016-08-24 17:15:14.898621
  timestamp.
* Windows: all events on ``we1149srv`` from 21:40:48.847339 to
  22:22:28.708445 UTC on 2016-08-10 (A), and all events on
  ``we8105desk`` from 15:39:33.015234 to 18:23:44.291567 UTC on
  2016-08-24 (B).  Only the labeled events are positives; the other events
  inside a window are benign hard negatives.

Expected totals: 659,112 network rows, 417 A positives, 48,199 B
positives, 610,496 benign, 40,521 A-window rows, 52,453 B-window rows.
"""
from __future__ import annotations

import gzip
import json
from datetime import datetime
from pathlib import Path

import pandas as pd

A_LO = datetime.fromisoformat("2016-08-10T21:40:48.847339+00:00")
A_HI = datetime.fromisoformat("2016-08-10T22:22:28.708445+00:00")
B_LO = datetime.fromisoformat("2016-08-24T15:39:33.015234+00:00")
B_HI = datetime.fromisoformat("2016-08-24T18:23:44.291567+00:00")
A_C2 = "108.161.187.134"
B_IE_TS_PREFIX = "2016-08-24T17:15:14.898621"
B_OSK_MARKER = "35aca89f"


def _host(r: dict) -> str:
    host = str(r.get("host") or r.get("Computer") or "")
    return host.split(".")[0]


def _ts(r: dict) -> tuple[str, datetime]:
    raw = str(r.get("TimeCreated") or "")
    if not raw:
        raw = str(r.get("UtcTime") or "")
    return raw, datetime.fromisoformat(raw.replace("Z", "+00:00"))


def load_botsv1_network(raw_path: str | Path) -> pd.DataFrame:
    """Return one row per Sysmon event code 3 with benchmark labels."""
    rows: list[dict] = []
    with gzip.open(raw_path, "rt", errors="replace") as fh:
        for line in fh:
            try:
                r = json.loads(line)["result"]
            except (KeyError, TypeError, json.JSONDecodeError):
                continue
            if str(r.get("EventCode")) != "3":
                continue
            tss, ts = _ts(r)
            host = _host(r)
            image = str(r.get("Image") or "")
            imgl = image.lower()
            dst_ip = str(r.get("DestinationIp") or "")

            in_a = host == "we1149srv" and A_LO <= ts <= A_HI
            in_b = host == "we8105desk" and B_LO <= ts <= B_HI
            is_a = dst_ip == A_C2 or (
                in_a and (
                    imgl.endswith("\\3791.exe")
                    or imgl.endswith("\\nslookup.exe")
                )
            )
            is_b = (
                B_OSK_MARKER in imgl and imgl.endswith("\\osk.exe")
            ) or (
                in_b
                and imgl.endswith("\\iexplore.exe")
                and tss.startswith(B_IE_TS_PREFIX)
            )

            label = 1 if (is_a or is_b) else 0
            campaign = "A" if is_a else ("B" if is_b else "")
            window = "A" if in_a else ("B" if in_b else "")
            rows.append({
                "ts": ts,
                "time": tss,
                "host": host,
                "user": str(r.get("User") or "-"),
                "guid": str(r.get("ProcessGuid") or ""),
                "pid": int(float(r.get("ProcessId") or 0)),
                "image": image,
                "src_ip": str(r.get("SourceIp") or ""),
                "src_port": int(float(r.get("SourcePort") or 0)),
                "dst_ip": dst_ip,
                "dst_port": int(float(r.get("DestinationPort") or 0)),
                "dst_host": str(r.get("DestinationHostname") or ""),
                "protocol": str(r.get("Protocol") or ""),
                "initiated": str(r.get("Initiated") or ""),
                "record_id": str(r.get("RecordID") or ""),
                "label": label,
                "campaign": campaign,
                "window": window,
            })

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    return df


def counts(df: pd.DataFrame) -> dict:
    """Small summary useful for asserting a rebuild."""
    return {
        "network_rows": int(len(df)),
        "positives": int(df["label"].sum()),
        "A": int((df["campaign"] == "A").sum()),
        "B": int((df["campaign"] == "B").sum()),
        "benign": int((df["label"] == 0).sum()),
        "window_A": int((df["window"] == "A").sum()),
        "window_B": int((df["window"] == "B").sum()),
    }


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("raw", nargs="?", default="datasets/botsv1/sysmon.json.gz")
    ap.add_argument("--assert-counts", action="store_true")
    args = ap.parse_args()
    frame = load_botsv1_network(args.raw)
    summary = counts(frame)
    print(json.dumps(summary, indent=2))
    if args.assert_counts:
        expected = {
            "network_rows": 659112, "positives": 48616,
            "A": 417, "B": 48199, "benign": 610496,
            "window_A": 40521, "window_B": 52453,
        }
        if summary != expected:
            raise SystemExit(f"count mismatch: {summary} != {expected}")
