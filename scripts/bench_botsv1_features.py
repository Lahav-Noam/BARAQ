#!/usr/bin/env python3
"""Extract BARAQ network features from the disposable BOTSv1 benchmark DB."""
from __future__ import annotations
import argparse, time
from pathlib import Path
import numpy as np, pandas as pd
from sqlalchemy import select
from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent
from backend.ml.anomaly import _load_network_features

OUT = Path('datasets/botsv1_bench')
OUT.mkdir(parents=True, exist_ok=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(OUT))
    args = ap.parse_args()
    out = Path(args.out)
    t = time.time()
    s = SessionLocal()
    rows = s.execute(select(NormalizedEvent.id, NormalizedEvent.timestamp,
                            NormalizedEvent.source, NormalizedEvent.raw_json)).all()
    print(f'metadata rows {len(rows):,} in {time.time()-t:.1f}s', flush=True)
    meta = {}
    for rid, ts, source, raw in rows:
        b = (raw or {}).get('benchmark') or {}
        meta[rid] = {
            'db_id': rid, 'ts': ts, 'source': source,
            'label': int(b.get('label', 0)),
            'campaign': b.get('campaign', ''), 'window': b.get('window', ''),
            'dataset': b.get('dataset', ''), 'host': b.get('host', ''),
            'guid': b.get('guid', ''), 'image': b.get('image', ''),
            'dst_ip': b.get('dst_ip', ''), 'dst_port': b.get('dst_port', 0),
            'dst_host': b.get('dst_host', ''),
        }
    print(f'metadata dict in {time.time()-t:.1f}s', flush=True)
    t2 = time.time()
    X, metas = _load_network_features(s, None, None)
    print(f'X {X.shape} metas {len(metas)} in {time.time()-t2:.1f}s', flush=True)
    ids = [m['event_id'] for m in metas]
    df = pd.DataFrame([meta[i] for i in ids])
    assert len(df) == len(X)
    df['bucket'] = df.apply(
        lambda r: pd.Timestamp(r['ts']).floor(
            '10min' if r['dataset'] == 'local' else '30min').isoformat(), axis=1)
    def grp(r):
        if r['label'] == 1:
            return f"attack_{r['campaign']}"
        if r['dataset'] == 'local':
            return 'local_bg'
        if r['window'] in ('A', 'B'):
            return f"hardneg_{r['window']}"
        return 'bg'
    df['group'] = df.apply(grp, axis=1)
    print(df.groupby(['dataset', 'label']).size())
    print(df.groupby(['campaign', 'label']).size())
    print('groups', df.group.value_counts().to_dict())
    np.savez_compressed(
        out / 'features.npz', X=X, y=df['label'].to_numpy(),
        db_id=df['db_id'].to_numpy(), bucket=df['bucket'].to_numpy(),
        campaign=df['campaign'].to_numpy(), window=df['window'].to_numpy(),
        dataset=df['dataset'].to_numpy(), group=df['group'].to_numpy(),
        host=df['host'].to_numpy(), image=df['image'].to_numpy(),
        dst_ip=df['dst_ip'].to_numpy(), dst_port=df['dst_port'].to_numpy(),
        ts=df['ts'].astype(str).to_numpy())
    df.to_pickle(out / 'meta.pkl')
    print(f'saved in {time.time()-t:.1f}s -> {out}', flush=True)

if __name__ == '__main__':
    main()
