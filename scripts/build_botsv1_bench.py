#!/usr/bin/env python3
"""Build a disposable BOTSv1 network benchmark database.

This script intentionally writes only to a database whose name ends in
``_bench``.  It never touches the live ``baraq`` database.

Inputs
------
``datasets/botsv1/sysmon.json.gz``
    The raw BOTSv1 Sysmon export.  ``scripts/botsv1_raw.py`` parses event code
    3 and reproduces the campaign C2/process labels and host/time windows.

``--source /path/to/labeled.pkl``
    Optional pre-labeled frame (legacy path).  If omitted, the raw gzip is
    parsed directly.

The live ``network_connections`` table is read only to add deduplicated local
benign flows as hard negatives.  ``--local-source`` reads a CSV snapshot
instead (``datasets/botsv1_bench/local_flows.csv`` is the original 5,201
flows).  Use ``--no-local`` for a BOTSv1-only rebuild.

Run:
    BARAQ_DATABASE_URL=postgresql+psycopg://.../baraq_ml_bench \
      python scripts/build_botsv1_bench.py \
      --raw-source datasets/botsv1/sysmon.json.gz \
      --local-source datasets/botsv1_bench/local_flows.csv
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Importing backend.config validates BARAQ_DATABASE_URL before we can guard it.
BENCH_URL = os.environ.get("BARAQ_DATABASE_URL", "")
if "_bench" not in BENCH_URL:
    raise SystemExit(
        "Refusing to run: BARAQ_DATABASE_URL must point at a *_bench database"
    )
os.environ.setdefault("BARAQ_ML_MODEL_BUNDLE", "/tmp/opencode/never-live.joblib")

from backend.database.connection import engine  # noqa: E402
from backend.database.models import Base, NormalizedEvent  # noqa: E402

LIVE_URL = os.environ.get(
    "BARAQ_LIVE_DATABASE_URL",
    "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/baraq",
)
RAW_SRC = Path("datasets/botsv1/sysmon.json.gz")


def _i(v, default=0):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def load_local(limit: int | None = None,
               source: str | None = None) -> pd.DataFrame:
    """Read and deduplicate outbound local connections (benign hard negatives).

    ``source`` may point at a CSV snapshot with the same columns as the live
    ``network_connections`` query.  This keeps the benchmark rebuild offline
    even after the live database has been rotated.
    """
    if source:
        df = pd.read_csv(source)
    else:
        live = create_engine(LIVE_URL, pool_pre_ping=True)
        try:
            df = pd.read_sql_query(
                text(
                    """
                    select id, pid, process, local_ip, local_port, remote_ip,
                           remote_port, state, is_listening, bytes_sent,
                           bytes_recv, observed_at
                    from network_connections
                    where coalesce(remote_ip, '') <> ''
                      and coalesce(is_listening, false) = false
                    order by observed_at, id
                    """
                ),
                live,
            )
        finally:
            live.dispose()
    if df.empty:
        return df
    df = df.drop_duplicates(
        subset=[
            "pid", "process", "local_ip", "local_port", "remote_ip",
            "remote_port", "state",
        ],
        keep="first",
    ).reset_index(drop=True)
    if limit:
        df = df.head(limit)
    return df


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=None,
                    help="optional pre-labeled pickle; otherwise parse raw")
    ap.add_argument("--raw-source", default=str(RAW_SRC))
    ap.add_argument("--batch", type=int, default=20000)
    ap.add_argument("--no-local", action="store_true")
    ap.add_argument("--local-limit", type=int, default=None)
    ap.add_argument("--local-source", default=None,
                    help="optional CSV snapshot of local network_connections")
    args = ap.parse_args()

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with Session() as s:
        s.execute(text("TRUNCATE TABLE verdicts, events RESTART IDENTITY CASCADE"))
        s.commit()

    if args.source:
        net = pd.read_pickle(args.source)
    else:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from botsv1_raw import load_botsv1_network

        print(f"parsing raw BOTSv1: {args.raw_source}", flush=True)
        net = load_botsv1_network(args.raw_source)
    net["ts"] = pd.to_datetime(net["ts"], utc=True)
    print(f"BOTSv1 network rows: {len(net):,} "
          f"(positive={int(net['label'].sum()):,}, "
          f"negative={int((net['label'] == 0).sum()):,})", flush=True)

    local = pd.DataFrame() if args.no_local else load_local(
        args.local_limit, args.local_source)
    if not local.empty:
        local["observed_at"] = pd.to_datetime(local["observed_at"], utc=True)
        print(f"local deduplicated flows: {len(local):,} "
              f"({local['observed_at'].min()} .. {local['observed_at'].max()})",
              flush=True)

    def net_rows():
        for r in net.itertuples(index=False):
            label = int(r.label)
            facts = {
                "source_ip": str(r.src_ip or ""),
                "remote_ip": str(r.dst_ip or ""),
                "remote_port": _i(r.dst_port),
                "protocol": str(r.protocol or ""),
                "destination_hostname": str(r.dst_host or ""),
                "process_name": str(r.image or ""),
                "process_guid": str(r.guid or ""),
            }
            yield {
                "event_id": 3,
                "category": "Network",
                "source": "botsv1",
                "user": str(r.user or "-")[:128],
                "host": str(r.host or "-")[:128],
                "org": "botsv1",
                "demo": True,
                "risk": "High" if label else "Low",
                "severity": "high" if label else "info",
                "message": f"{r.image} -> {r.dst_ip}:{r.dst_port} {r.dst_host}"[:1000],
                "timestamp": r.ts.to_pydatetime(),
                "data_integrity": "complete",
                "raw_json": {
                    "facts": facts,
                    "benchmark": {
                        "label": label,
                        "campaign": str(r.campaign or ""),
                        "window": str(r.window or ""),
                        "dataset": "botsv1",
                        "host": str(r.host or ""),
                        "guid": str(r.guid or ""),
                        "image": str(r.image or ""),
                        "dst_ip": str(r.dst_ip or ""),
                        "dst_port": _i(r.dst_port),
                        "dst_host": str(r.dst_host or ""),
                    },
                },
                "is_anomaly": False,
            }

    def local_rows():
        for r in local.itertuples(index=False):
            facts = {
                "source_ip": str(r.local_ip or ""),
                "remote_ip": str(r.remote_ip or ""),
                "remote_port": _i(r.remote_port),
                "protocol": "tcp",
                "process_name": str(r.process or ""),
            }
            yield {
                "event_id": 3,
                "category": "Network",
                "source": "local",
                "user": "-",
                "host": "local",
                "org": "local",
                "demo": True,
                "risk": "Low",
                "severity": "info",
                "message": f"{r.process} -> {r.remote_ip}:{r.remote_port}"[:1000],
                "timestamp": r.observed_at.to_pydatetime(),
                "data_integrity": "complete",
                "raw_json": {
                    "facts": facts,
                    "benchmark": {
                        "label": 0,
                        "campaign": "local",
                        "window": "local",
                        "dataset": "local",
                        "host": "local",
                        "guid": "",
                        "image": str(r.process or ""),
                        "dst_ip": str(r.remote_ip or ""),
                        "dst_port": _i(r.remote_port),
                        "dst_host": "",
                    },
                },
                "is_anomaly": False,
            }

    total = 0
    with Session() as s:
        for name, it in (("botsv1", net_rows()), ("local", local_rows())):
            batch = []
            for row in it:
                batch.append(row)
                if len(batch) >= args.batch:
                    s.bulk_insert_mappings(NormalizedEvent, batch)
                    s.commit()
                    total += len(batch)
                    print(f"  {name}: inserted {total:,}", flush=True)
                    batch = []
            if batch:
                s.bulk_insert_mappings(NormalizedEvent, batch)
                s.commit()
                total += len(batch)
                print(f"  {name}: inserted {total:,}", flush=True)

    with Session() as s:
        n_events = s.execute(text("select count(*) from events")).scalar_one()
        n_pos = s.execute(
            text("select count(*) from events where (raw_json->'benchmark'->>'label') = '1'")
        ).scalar_one()
        n_local = s.execute(
            text("select count(*) from events where source = 'local'")
        ).scalar_one()
    print(f"done: events={n_events:,} positives={n_pos:,} local={n_local:,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
