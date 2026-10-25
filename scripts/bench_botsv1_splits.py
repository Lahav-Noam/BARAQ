"""Grouped/time-based splits for the BOTSv1 network benchmark."""
from __future__ import annotations
import numpy as np, pandas as pd

def _time_assign(meta, mask, frac=(0.6, 0.2, 0.2)):
    idx = np.where(mask)[0]
    buckets = sorted(meta.iloc[idx]['bucket'].unique())
    n = len(buckets)
    ntr = max(1, int(round(frac[0] * n)))
    nva = max(1, int(round(frac[1] * n)))
    nte = n - ntr - nva
    if nte < 1:
        nte = 1
        ntr = max(1, n - nva - nte)
    bs = {}
    for i, b in enumerate(buckets):
        bs[b] = 'train' if i < ntr else ('val' if i < ntr + nva else 'test')
    return bs

def _ip_group_assign(meta, mask, seed=42, frac=(0.7, 0.15, 0.15)):
    idx = np.where(mask)[0]
    ips = sorted(meta.iloc[idx]['dst_ip'].astype(str).unique())
    rng = np.random.default_rng(seed)
    rng.shuffle(ips)
    n = len(ips)
    ntr = int(round(frac[0] * n)); nva = int(round(frac[1] * n)); nte = n - ntr - nva
    if nte < 1:
        nte = 1; ntr = n - nva - nte
    return {ip: ('train' if i < ntr else ('val' if i < ntr + nva else 'test'))
            for i, ip in enumerate(ips)}

def _local_time_split(meta, sp):
    lm = (meta.dataset == 'local').to_numpy()
    li = np.where(lm)[0]
    li = li[np.argsort(meta.iloc[li]['ts'].values)]
    n = len(li); ntr = int(round(.7 * n)); nva = int(round(.1 * n))
    sp[li[:ntr]] = 'train'; sp[li[ntr:ntr + nva]] = 'val'; sp[li[ntr + nva:]] = 'test'

def split_s1(meta, seed=42):
    """Within-campaign holdout: B held out by unseen destination IP; A by time."""
    sp = np.full(len(meta), '', dtype=object)
    b = (meta.dataset == 'botsv1').to_numpy()
    a = (meta.campaign == 'A').to_numpy()
    sp[a] = meta.loc[a, 'bucket'].map(_time_assign(meta, a, (.6, .2, .2))).to_numpy()
    bm = (meta.campaign == 'B').to_numpy()
    sp[bm] = meta.loc[bm, 'dst_ip'].astype(str).map(
        _ip_group_assign(meta, bm, seed, (.7, .15, .15))).to_numpy()
    for camp in ['A', 'B']:
        m = b & (meta.label == 0).to_numpy() & (meta.window == camp).to_numpy()
        sp[m] = meta.loc[m, 'bucket'].map(_time_assign(meta, m, (.6, .2, .2))).to_numpy()
    bgm = b & (meta.label == 0).to_numpy() & (~meta.window.isin(['A', 'B']).to_numpy())
    buckets = sorted(meta.loc[bgm, 'bucket'].unique())
    rng = np.random.default_rng(seed); rng.shuffle(buckets)
    n = len(buckets); ntr = int(round(.7 * n)); nva = int(round(.15 * n))
    bs = {bk: 'train' for bk in buckets[:ntr]}
    bs.update({bk: 'val' for bk in buckets[ntr:ntr + nva]})
    bs.update({bk: 'test' for bk in buckets[ntr + nva:]})
    sp[bgm] = meta.loc[bgm, 'bucket'].map(bs).to_numpy()
    _local_time_split(meta, sp)
    return sp

def split_cross(meta, direction='A_to_B', seed=42):
    """Leave-one-campaign-out: train on one attack campaign, test on the other."""
    sp = np.full(len(meta), '', dtype=object)
    b = (meta.dataset == 'botsv1').to_numpy()
    ts = pd.to_datetime(meta.ts, utc=True)
    aug21 = pd.Timestamp('2016-08-21 00:00', tz='UTC')
    aug24 = pd.Timestamp('2016-08-24 00:00', tz='UTC')
    if direction == 'A_to_B':
        a = (meta.campaign == 'A').to_numpy()
        early = b & (ts < aug21).to_numpy() & ~a
        mid = b & (ts >= aug21).to_numpy() & (ts < aug24).to_numpy()
        late = b & (ts >= aug24).to_numpy() & ~(meta.campaign == 'B').to_numpy()
        test = (meta.campaign == 'B').to_numpy() | late
        a_early = a & (ts < aug21).to_numpy()
        sp[a_early] = meta.loc[a_early, 'bucket'].map(
            _time_assign(meta, a_early, (.8, .2, 0))).to_numpy()
        sp[a & (ts >= aug21).to_numpy()] = 'val'
        sp[early] = meta.loc[early, 'bucket'].map(
            _time_assign(meta, early, (.9, .1, 0))).to_numpy()
        sp[mid] = 'val'; sp[test] = 'test'
    elif direction == 'B_to_A':
        bm = (meta.campaign == 'B').to_numpy()
        late = b & (ts >= aug24).to_numpy() & ~bm
        early = b & (ts < aug21).to_numpy() & ~(meta.campaign == 'A').to_numpy()
        mid = b & (ts >= aug21).to_numpy() & (ts < aug24).to_numpy()
        sp[bm] = meta.loc[bm, 'dst_ip'].astype(str).map(
            _ip_group_assign(meta, bm, seed, (.8, .2, 0))).to_numpy()
        sp[late] = meta.loc[late, 'bucket'].map(
            _time_assign(meta, late, (.9, .1, 0))).to_numpy()
        sp[mid] = 'val'
        sp[(meta.campaign == 'A').to_numpy() | early] = 'test'
    _local_time_split(meta, sp)
    return sp

if __name__ == '__main__':
    meta = pd.read_pickle('datasets/botsv1_bench/meta.pkl')
    for name, sp in [('S1', split_s1(meta)),
                     ('S2_AtoB', split_cross(meta, 'A_to_B')),
                     ('S3_BtoA', split_cross(meta, 'B_to_A'))]:
        m = meta.copy(); m['split'] = sp
        print('\n===', name)
        print(m.groupby(['split', 'dataset', 'label']).size().to_string())
        print('test campaigns', m[(m.split == 'test') & (m.label == 1)].campaign.value_counts().to_dict())
        print('unassigned', (sp == '').sum())
