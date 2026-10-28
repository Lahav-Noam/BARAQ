#!/usr/bin/env python3
"""
High-level network ML detector — canonical implementation.

This module provides:
1. A causal, streaming feature schema (FEATURES, FEATURE_VERSION)
2. A streaming Profiler for incremental feature extraction
3. A candidate HighLevelDetector combining Isolation Forest + rule fusion

The detector is designed for SHADOW/ADVISORY deployment only — it never
mutates events or triggers autonomous responses.
"""
from __future__ import annotations
import json
import math
import hashlib
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.isotonic import IsotonicRegression

from backend.database.models import NetworkConnection, MLShadowScore
from backend.database.connection import SessionLocal

logger = logging.getLogger(__name__)

# ============================================================
# FEATURE SCHEMA — single source of truth
# ============================================================
FEATURES = [
    'hour_sin','hour_cos','is_night','is_weekend',
    'dst_port_norm','port_rarity','port_host_fanout_log','port_is_well_known','port_is_high',
    'dst_private','dst_loopback','dst_multicast','dst_novel','dst_count_log','dst_host_fanout_log',
    'src_host_count_log','src_fanout_log','src_port_fanout_log','src_process_fanout_log',
    'process_seen','process_count_log','process_rarity','process_host_fanout_log','process_user_writable','process_system_path','process_path_entropy','process_name_len',
    'pair_novel','pair_count_log','pair_time_since_log','pair_interval_cv','pair_interval_entropy','pair_regularity','pair_small_flow_ratio',
    'host_rate_1m','host_rate_10m','host_new_dst_ratio','host_distinct_ports_10m','host_dst_fanout_ratio',
    'domain_present','domain_novel','domain_entropy','domain_digit_ratio','domain_label_count','domain_len_log',
    'bytes_sent_log','bytes_recv_log','bytes_asymmetry','bytes_per_sec_log','duration_log',
    'service_dns','service_http','service_ssl','service_smb','service_dce_rpc','conn_s0','conn_rej','conn_rsto',
    # external/fan-in/fan-out interactions
    'ext_dst_novel','ext_dst_count_log','ext_dst_host_fanout_log','ext_dst_proc_fanout_log','ext_dst_port_fanout_log',
    'ext_proc_host_fanout_log','ext_proc_ratio','ext_port_host_fanout_log',
    'ext_src_fanout_log','ext_src_new_ratio','ext_host_ext_ratio','ext_src_distinct_ports_log',
    'ext_dst_src_ratio','ext_dst_per_host_ratio','ext_pair_novel','ext_pair_count_log',
    'ext_dst_fanin_x_count','ext_src_fanout_x_ports','ext_proc_hosts_x_ext_ratio',
    # process/host-process context
    'ext_proc_dst_novel','ext_proc_port_novel','ext_proc_pair_novel',
    'ext_host_proc_dst_novel','ext_host_proc_pair_novel',
    'ext_proc_dst_count_log','ext_proc_dst_host_fanout_log','ext_proc_ext_dst_fanout_log','ext_proc_ext_port_fanout_log',
    'ext_proc_ext_count_log','ext_proc_ext_ratio_x_count','ext_proc_ext_ratio_x_hosts',
    'ext_host_proc_ext_ratio','ext_host_proc_dst_fanout_log','ext_host_proc_new_ratio',
]

FEATURE_VERSION = 1
N_FEATURES = len(FEATURES)
FEATURE_INDEX = {name: i for i, name in enumerate(FEATURES)}


# ============================================================
# HELPERS
# ============================================================
def _entropy(vals):
    if not vals:
        return 0.0
    c = defaultdict(int)
    for v in vals:
        c[v] += 1
    n = len(vals)
    h = -sum((x/n) * math.log2(x/n) for x in c.values())
    return h / math.log2(max(2, len(c)))

def _path_entropy(s: str) -> float:
    return _entropy(list(s.lower())) if s else 0.0

def _domain_shape(d: str) -> tuple[float, float, float, float, float]:
    d = (d or '').strip().lower()
    if not d:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    labels = d.split('.')
    digits = sum(ch.isdigit() for ch in d) / max(1, len(d))
    return 1.0, _entropy(list(d)), digits, float(len(labels)), float(len(d))

def _is_private(ip: str) -> bool:
    return ip.startswith(('10.','192.168.','172.16.','172.17.','172.18.','172.19.','172.2','172.3','127.'))


# ============================================================
# DATA STRUCTURES
# ============================================================
@dataclass
class Flow:
    """Normalized network flow for feature extraction."""
    ts: float
    src: str = ''
    dst: str = ''
    port: int = 0
    process: str = ''
    domain: str = ''
    service: str = ''
    state: str = ''
    bsent: int = 0
    brecv: int = 0
    duration: float = 0.0


@dataclass
class ProfilerState:
    """Serializable profiler state for persistence."""
    n: int = 0
    host_count: dict[str, int] = field(default_factory=dict)
    host_dsts: dict[str, list[str]] = field(default_factory=dict)
    host_ports: dict[str, list[int]] = field(default_factory=dict)
    host_procs: dict[str, list[str]] = field(default_factory=dict)
    host_ext_flows: dict[str, int] = field(default_factory=dict)
    host_ext_dsts: dict[str, list[str]] = field(default_factory=dict)
    host_ext_ports: dict[str, list[int]] = field(default_factory=dict)
    proc_count: dict[str, int] = field(default_factory=dict)
    proc_hosts: dict[str, list[str]] = field(default_factory=dict)
    proc_ext_count: dict[str, int] = field(default_factory=dict)
    proc_ext_hosts: dict[str, list[str]] = field(default_factory=dict)
    dst_count: dict[str, int] = field(default_factory=dict)
    dst_hosts: dict[str, list[str]] = field(default_factory=dict)
    dst_ports: dict[str, list[int]] = field(default_factory=dict)
    dst_procs: dict[str, list[str]] = field(default_factory=dict)
    port_count: dict[str, int] = field(default_factory=dict)
    port_hosts: dict[str, list[str]] = field(default_factory=dict)
    domain_count: dict[str, int] = field(default_factory=dict)
    domain_hosts: dict[str, list[str]] = field(default_factory=dict)
    pair_ts: dict[str, list[float]] = field(default_factory=dict)
    pair_count: dict[str, int] = field(default_factory=dict)
    pair_ext_count: dict[str, int] = field(default_factory=dict)
    host_ts: dict[str, list[float]] = field(default_factory=dict)
    proc_dsts: dict[str, list[str]] = field(default_factory=dict)
    proc_ports: dict[str, list[int]] = field(default_factory=dict)
    proc_pairs: dict[str, list[str]] = field(default_factory=dict)
    proc_ext_dsts: dict[str, list[str]] = field(default_factory=dict)
    proc_ext_ports: dict[str, list[int]] = field(default_factory=dict)
    proc_dst_hosts: dict[str, list[str]] = field(default_factory=dict)
    proc_dst_count: dict[str, int] = field(default_factory=dict)
    proc_pair_count: dict[str, int] = field(default_factory=dict)
    host_proc_dsts: dict[str, list[str]] = field(default_factory=dict)
    host_proc_pairs: dict[str, list[str]] = field(default_factory=dict)
    host_proc_ext_dsts: dict[str, list[str]] = field(default_factory=dict)
    host_proc_ext_ports: dict[str, list[int]] = field(default_factory=dict)
    host_proc_count: dict[str, int] = field(default_factory=dict)
    host_proc_ext_count: dict[str, int] = field(default_factory=dict)


class Profiler:
    """
    Causal streaming profiler — state updated AFTER feature computation.

    This ensures no look-ahead leakage: features for flow N depend only on
    flows 0..N-1.
    """
    __slots__ = (
        'n',
        'host_count', 'host_dsts', 'host_ports', 'host_procs',
        'host_ext_flows', 'host_ext_dsts', 'host_ext_ports',
        'proc_count', 'proc_hosts', 'proc_ext_count', 'proc_ext_hosts',
        'dst_count', 'dst_hosts', 'dst_ports', 'dst_procs',
        'port_count', 'port_hosts',
        'domain_count', 'domain_hosts',
        'pair_ts', 'pair_count', 'pair_ext_count',
        'host_ts',
        'proc_dsts', 'proc_ports', 'proc_pairs',
        'proc_ext_dsts', 'proc_ext_ports',
        'proc_dst_hosts', 'proc_dst_count', 'proc_pair_count',
        'host_proc_dsts', 'host_proc_pairs', 'host_proc_ext_dsts', 'host_proc_ext_ports',
        'host_proc_count', 'host_proc_ext_count',
    )

    def __init__(self):
        self.n = 0
        self.host_count = defaultdict(int)
        self.host_dsts = defaultdict(set)
        self.host_ports = defaultdict(set)
        self.host_procs = defaultdict(set)
        self.host_ext_flows = defaultdict(int)
        self.host_ext_dsts = defaultdict(set)
        self.host_ext_ports = defaultdict(set)
        self.proc_count = defaultdict(int)
        self.proc_hosts = defaultdict(set)
        self.proc_ext_count = defaultdict(int)
        self.proc_ext_hosts = defaultdict(set)
        self.dst_count = defaultdict(int)
        self.dst_hosts = defaultdict(set)
        self.dst_ports = defaultdict(set)
        self.dst_procs = defaultdict(set)
        self.port_count = defaultdict(int)
        self.port_hosts = defaultdict(set)
        self.domain_count = defaultdict(int)
        self.domain_hosts = defaultdict(set)
        self.pair_ts = defaultdict(lambda: deque(maxlen=32))
        self.pair_count = defaultdict(int)
        self.pair_ext_count = defaultdict(int)
        self.host_ts = defaultdict(lambda: deque(maxlen=256))
        # process/host-process context
        self.proc_dsts = defaultdict(set)
        self.proc_ports = defaultdict(set)
        self.proc_pairs = defaultdict(set)
        self.proc_ext_dsts = defaultdict(set)
        self.proc_ext_ports = defaultdict(set)
        self.proc_dst_hosts = defaultdict(set)
        self.proc_dst_count = defaultdict(int)
        self.proc_pair_count = defaultdict(int)
        self.host_proc_dsts = defaultdict(set)
        self.host_proc_pairs = defaultdict(set)
        self.host_proc_ext_dsts = defaultdict(set)
        self.host_proc_ext_ports = defaultdict(set)
        self.host_proc_count = defaultdict(int)
        self.host_proc_ext_count = defaultdict(int)

    def to_state(self) -> ProfilerState:
        """Serialize to a portable state object."""
        def set_to_list(d):
            return {k: list(v) for k, v in d.items()}
        return ProfilerState(
            n=self.n,
            host_count=dict(self.host_count),
            host_dsts=set_to_list(self.host_dsts),
            host_ports=set_to_list(self.host_ports),
            host_procs=set_to_list(self.host_procs),
            host_ext_flows=dict(self.host_ext_flows),
            host_ext_dsts=set_to_list(self.host_ext_dsts),
            host_ext_ports=set_to_list(self.host_ext_ports),
            proc_count=dict(self.proc_count),
            proc_hosts=set_to_list(self.proc_hosts),
            proc_ext_count=dict(self.proc_ext_count),
            proc_ext_hosts=set_to_list(self.proc_ext_hosts),
            dst_count=dict(self.dst_count),
            dst_hosts=set_to_list(self.dst_hosts),
            dst_ports=set_to_list(self.dst_ports),
            dst_procs=set_to_list(self.dst_procs),
            port_count=dict(self.port_count),
            port_hosts=set_to_list(self.port_hosts),
            domain_count=dict(self.domain_count),
            domain_hosts=set_to_list(self.domain_hosts),
            pair_ts={k: list(v) for k, v in self.pair_ts.items()},
            pair_count=dict(self.pair_count),
            pair_ext_count=dict(self.pair_ext_count),
            host_ts={k: list(v) for k, v in self.host_ts.items()},
            proc_dsts=set_to_list(self.proc_dsts),
            proc_ports=set_to_list(self.proc_ports),
            proc_pairs={k: [f"{a}:{b}" for a,b in v] for k, v in self.proc_pairs.items()},
            proc_ext_dsts=set_to_list(self.proc_ext_dsts),
            proc_ext_ports=set_to_list(self.proc_ext_ports),
            proc_dst_hosts=set_to_list(self.proc_dst_hosts),
            proc_dst_count=dict(self.proc_dst_count),
            proc_pair_count=dict(self.proc_pair_count),
            host_proc_dsts=set_to_list(self.host_proc_dsts),
            host_proc_pairs={k: [f"{a}:{b}" for a,b in v] for k, v in self.host_proc_pairs.items()},
            host_proc_ext_dsts=set_to_list(self.host_proc_ext_dsts),
            host_proc_ext_ports=set_to_list(self.host_proc_ext_ports),
            host_proc_count=dict(self.host_proc_count),
            host_proc_ext_count=dict(self.host_proc_ext_count),
        )

    @classmethod
    def from_state(cls, state: ProfilerState) -> 'Profiler':
        """Reconstruct profiler from serialized state."""
        p = cls()
        p.n = state.n
        p.host_count = defaultdict(int, state.host_count)
        p.host_dsts = defaultdict(set, {k: set(v) for k, v in state.host_dsts.items()})
        p.host_ports = defaultdict(set, {k: set(v) for k, v in state.host_ports.items()})
        p.host_procs = defaultdict(set, {k: set(v) for k, v in state.host_procs.items()})
        p.host_ext_flows = defaultdict(int, state.host_ext_flows)
        p.host_ext_dsts = defaultdict(set, {k: set(v) for k, v in state.host_ext_dsts.items()})
        p.host_ext_ports = defaultdict(set, {k: set(v) for k, v in state.host_ext_ports.items()})
        p.proc_count = defaultdict(int, state.proc_count)
        p.proc_hosts = defaultdict(set, {k: set(v) for k, v in state.proc_hosts.items()})
        p.proc_ext_count = defaultdict(int, state.proc_ext_count)
        p.proc_ext_hosts = defaultdict(set, {k: set(v) for k, v in state.proc_ext_hosts.items()})
        p.dst_count = defaultdict(int, state.dst_count)
        p.dst_hosts = defaultdict(set, {k: set(v) for k, v in state.dst_hosts.items()})
        p.dst_ports = defaultdict(set, {k: set(v) for k, v in state.dst_ports.items()})
        p.dst_procs = defaultdict(set, {k: set(v) for k, v in state.dst_procs.items()})
        p.port_count = defaultdict(int, state.port_count)
        p.port_hosts = defaultdict(set, {k: set(v) for k, v in state.port_hosts.items()})
        p.domain_count = defaultdict(int, state.domain_count)
        p.domain_hosts = defaultdict(set, {k: set(v) for k, v in state.domain_hosts.items()})
        p.pair_ts = defaultdict(lambda: deque(maxlen=32), {k: deque(v, maxlen=32) for k, v in state.pair_ts.items()})
        p.pair_count = defaultdict(int, state.pair_count)
        p.pair_ext_count = defaultdict(int, state.pair_ext_count)
        p.host_ts = defaultdict(lambda: deque(maxlen=256), {k: deque(v, maxlen=256) for k, v in state.host_ts.items()})
        p.proc_dsts = defaultdict(set, {k: set(v) for k, v in state.proc_dsts.items()})
        p.proc_ports = defaultdict(set, {k: set(v) for k, v in state.proc_ports.items()})
        p.proc_pairs = defaultdict(set, {k: {tuple(x.split(':',1)) for x in v} for k, v in state.proc_pairs.items()})
        p.proc_ext_dsts = defaultdict(set, {k: set(v) for k, v in state.proc_ext_dsts.items()})
        p.proc_ext_ports = defaultdict(set, {k: set(v) for k, v in state.proc_ext_ports.items()})
        p.proc_dst_hosts = defaultdict(set, {k: set(v) for k, v in state.proc_dst_hosts.items()})
        p.proc_dst_count = defaultdict(int, state.proc_dst_count)
        p.proc_pair_count = defaultdict(int, state.proc_pair_count)
        p.host_proc_dsts = defaultdict(set, {k: set(v) for k, v in state.host_proc_dsts.items()})
        p.host_proc_pairs = defaultdict(set, {k: {tuple(x.split(':',1)) for x in v} for k, v in state.host_proc_pairs.items()})
        p.host_proc_ext_dsts = defaultdict(set, {k: set(v) for k, v in state.host_proc_ext_dsts.items()})
        p.host_proc_ext_ports = defaultdict(set, {k: set(v) for k, v in state.host_proc_ext_ports.items()})
        p.host_proc_count = defaultdict(int, state.host_proc_count)
        p.host_proc_ext_count = defaultdict(int, state.host_proc_ext_count)
        return p

    def features(self, f: Flow) -> np.ndarray:
        """Compute feature vector for flow f using current state (causal)."""
        dt = datetime.fromtimestamp(f.ts, UTC)
        hour = dt.hour
        hour_sin = math.sin(2 * math.pi * hour / 24)
        hour_cos = math.cos(2 * math.pi * hour / 24)
        is_night = 1.0 if hour in (22, 23, 0, 1, 2, 3, 4, 5) else 0.0
        is_weekend = 1.0 if dt.weekday() >= 5 else 0.0

        dst = f.dst or ''
        port = int(f.port or 0)
        src = f.src or ''
        proc = f.process or ''
        priv = _is_private(dst)
        ext = 1.0 - (1.0 if priv else 0.0)
        n = max(1, self.n)

        dst_novel = 1.0 if dst and self.dst_count.get(dst, 0) == 0 else 0.0
        port_rarity = 1.0 - (self.port_count.get(port, 0) / n) if port else 0.0

        pc = self.proc_count.get(proc, 0)
        pec = self.proc_ext_count.get(proc, 0)
        process_rarity = 1.0 - (pc / n) if proc else 1.0

        proc_low = proc.lower()
        user_writable = 1.0 if any(t in proc_low for t in (
            '\\appdata\\', '/tmp/', '\\temp\\', '\\downloads\\', '\\public\\', '/home/', '/var/tmp/')) else 0.0
        system_path = 1.0 if any(t in proc_low for t in (
            '\\windows\\system32\\', '\\windows\\syswow64\\', '/usr/bin/', '/usr/sbin/', '/bin/')) else 0.0

        pkey = (src, dst, port)
        pts = self.pair_ts.get(pkey)
        pair_ct = self.pair_count.get(pkey, 0)
        if pts and len(pts) >= 2:
            arr = np.asarray(pts, dtype=float)
            intervals = np.diff(arr)
            mean = float(intervals.mean()) if len(intervals) else 0.0
            cv = float(intervals.std() / mean) if mean > 1e-9 else 0.0
            ient = _entropy([round(float(x), 1) for x in intervals])
            beac = 1.0 / (1.0 + cv) if len(intervals) >= 2 else 0.0
            time_since = float(f.ts - arr[-1]) if f.ts >= arr[-1] else 0.0
        else:
            cv = 0.0
            ient = 0.0
            beac = 0.0
            time_since = 0.0
        pair_novel = 1.0 if pair_ct == 0 else 0.0

        hts = self.host_ts.get(src)
        rate1 = rate10 = 0.0
        if hts:
            arr = np.asarray(hts, dtype=float)
            rate1 = float(((f.ts - arr) <= 60).sum())
            rate10 = float(((f.ts - arr) <= 600).sum()) / 10.0

        dom = f.domain or ''
        dp, de, dd, dl, dlen = _domain_shape(dom)
        dnovel = 1.0 if dom and self.domain_count.get(dom, 0) == 0 else 0.0

        bs = max(0, f.bsent or 0)
        br = max(0, f.brecv or 0)
        dur = max(0, f.duration or 0)
        sent_log = math.log1p(bs)
        recv_log = math.log1p(br)
        asym = (bs + 1) / (br + 1)
        bps = (bs + br) / max(dur, 1e-3) if (bs + br) > 0 else 0.0

        service = (f.service or '').lower()
        state = (f.state or '').upper()
        svc = lambda x: 1.0 if x in service else 0.0

        # External interaction features
        dst_hosts = len(self.dst_hosts.get(dst, ()))
        dst_procs = len(self.dst_procs.get(dst, ()))
        dst_ports = len(self.dst_ports.get(dst, ()))
        src_ext = len(self.host_ext_dsts.get(src, ()))
        src_all = len(self.host_dsts.get(src, ()))
        proc_ext_hosts = len(self.proc_ext_hosts.get(proc, ()))
        proc_hosts = len(self.proc_hosts.get(proc, ()))
        ext_pair_ct = self.pair_ext_count.get(pkey, 0)

        e_dst_novel = ext * dst_novel
        e_dst_count = ext * math.log1p(self.dst_count.get(dst, 0))
        e_dst_hosts = ext * math.log1p(dst_hosts)
        e_dst_procs = ext * math.log1p(dst_procs)
        e_dst_ports = ext * math.log1p(dst_ports)
        e_proc_hosts = ext * math.log1p(proc_ext_hosts)
        e_proc_ratio = ext * (pec / (pc + 1))
        e_port_hosts = ext * math.log1p(len(self.port_hosts.get(port, ())))
        e_src_fanout = ext * math.log1p(src_ext)
        e_src_new = ext * (1.0 - (self.host_ext_flows.get(src, 0) / max(1, self.host_count.get(src, 0))))
        e_host_ratio = self.host_ext_flows.get(src, 0) / max(1, self.host_count.get(src, 0))
        e_src_ports = ext * math.log1p(len(self.host_ext_ports.get(src, ())))
        e_dst_src_ratio = ext * ((dst_hosts + 1) / (src_all + 1))
        e_dst_per_host = ext * ((dst_hosts + 1) / (len(self.host_dsts.get(src, ())) + 1))
        e_pair_novel = ext * pair_novel
        e_pair_count = ext * math.log1p(ext_pair_ct)
        e_fanin_x_count = e_dst_hosts * e_dst_count
        e_fanout_x_ports = e_src_fanout * e_src_ports
        e_proc_x_ratio = e_proc_hosts * e_proc_ratio

        # Process/host-process context
        hpk = (src, proc)
        proc_dst_n = 1.0 if (proc, dst) not in self.proc_dst_count else 0.0
        proc_port_n = 1.0 if port not in self.proc_ports.get(proc, ()) else 0.0
        proc_pair_n = 1.0 if (proc, dst, port) not in self.proc_pair_count else 0.0
        host_proc_dst_n = 1.0 if dst not in self.host_proc_dsts.get(hpk, ()) else 0.0
        host_proc_pair_n = 1.0 if (dst, port) not in self.host_proc_pairs.get(hpk, ()) else 0.0
        proc_dst_count = self.proc_dst_count.get((proc, dst), 0)
        proc_dst_hosts = len(self.proc_dst_hosts.get((proc, dst), ()))
        proc_ext_dsts = len(self.proc_ext_dsts.get(proc, ()))
        proc_ext_ports = len(self.proc_ext_ports.get(proc, ()))
        proc_ext_ct = self.proc_ext_count.get(proc, 0)
        host_proc_ct = self.host_proc_count.get(hpk, 0)
        host_proc_ext_ct = self.host_proc_ext_count.get(hpk, 0)
        hproc_ratio = host_proc_ext_ct / max(1, host_proc_ct)
        hproc_ext_dsts = len(self.host_proc_ext_dsts.get(hpk, ()))
        hproc_new_ratio = 1.0 - (host_proc_ext_ct / max(1, host_proc_ct)) if host_proc_ct else 1.0

        return np.array([
            hour_sin, hour_cos, is_night, is_weekend,
            port / 65535.0, port_rarity, math.log1p(len(self.port_hosts.get(port, ()))), 1.0 if 0 < port < 1024 else 0.0, 1.0 if port >= 49152 else 0.0,
            1.0 if priv else 0.0, 1.0 if dst in ('127.0.0.1', '::1') else 0.0, 1.0 if dst.startswith(('224.', '239.', '255.')) else 0.0,
            dst_novel, math.log1p(self.dst_count.get(dst, 0)), math.log1p(dst_hosts),
            math.log1p(self.host_count.get(src, 0)), math.log1p(len(self.host_dsts.get(src, ()))), math.log1p(len(self.host_ports.get(src, ()))), math.log1p(len(self.host_procs.get(src, ()))),
            1.0 if pc > 0 else 0.0, math.log1p(pc), process_rarity, math.log1p(proc_hosts), user_writable, system_path, _path_entropy(proc), math.log1p(len(proc)),
            pair_novel, math.log1p(pair_ct), math.log1p(1 + time_since), cv, ient, beac, 0.0,
            rate1, rate10, 0.0, 0.0, (len(self.host_dsts.get(src, ())) + 1) / (len(self.dst_hosts.get(dst, ())) + 1),
            dp, dnovel, de, dd, dl, math.log1p(dlen),
            sent_log, recv_log, asym, math.log1p(bps), math.log1p(dur),
            svc('dns'), svc('http'), svc('ssl'), svc('smb'), svc('dce_rpc'), 1.0 if state.startswith('S0') else 0.0, 1.0 if state in ('REJ', 'RST') else 0.0, 1.0 if state.startswith('RSTO') else 0.0,
            e_dst_novel, e_dst_count, e_dst_hosts, e_dst_procs, e_dst_ports,
            e_proc_hosts, e_proc_ratio, e_port_hosts,
            e_src_fanout, e_src_new, e_host_ratio, e_src_ports,
            e_dst_src_ratio, e_dst_per_host, e_pair_novel, e_pair_count,
            e_fanin_x_count, e_fanout_x_ports, e_proc_x_ratio,
            ext * proc_dst_n, ext * proc_port_n, ext * proc_pair_n,
            ext * host_proc_dst_n, ext * host_proc_pair_n,
            ext * math.log1p(proc_dst_count), ext * math.log1p(proc_dst_hosts), ext * math.log1p(proc_ext_dsts), ext * math.log1p(proc_ext_ports),
            ext * math.log1p(proc_ext_ct), ext * e_proc_ratio * math.log1p(proc_ext_ct), ext * e_proc_ratio * math.log1p(proc_hosts),
            ext * math.log1p(host_proc_ext_ct) * hproc_ratio, ext * math.log1p(hproc_ext_dsts), ext * hproc_new_ratio,
        ], dtype=np.float32)

    def update(self, f: Flow):
        """Update state AFTER feature computation (causal)."""
        self.n += 1
        src = f.src or ''
        dst = f.dst or ''
        port = int(f.port or 0)
        proc = f.process or ''
        dom = f.domain or ''
        ext = not _is_private(dst)

        self.host_count[src] += 1
        self.host_dsts[src].add(dst)
        self.host_ports[src].add(port)
        self.host_procs[src].add(proc)
        if ext:
            self.host_ext_flows[src] += 1
            self.host_ext_dsts[src].add(dst)
            self.host_ext_ports[src].add(port)

        self.proc_count[proc] += 1
        self.proc_hosts[proc].add(src)
        if ext:
            self.proc_ext_count[proc] += 1
            self.proc_ext_hosts[proc].add(src)

        if dst:
            self.dst_count[dst] += 1
            self.dst_hosts[dst].add(src)
            self.dst_ports[dst].add(port)
            self.dst_procs[dst].add(proc)

        self.port_count[port] += 1
        self.port_hosts[port].add(src)

        if dom:
            self.domain_count[dom] += 1
            self.domain_hosts[dom].add(src)

        pkey = (src, dst, port)
        self.pair_count[pkey] += 1
        self.pair_ext_count[pkey] += (1 if ext else 0)
        self.pair_ts[pkey].append(f.ts)

        self.proc_dsts[proc].add(dst)
        self.proc_ports[proc].add(port)
        self.proc_pairs[proc].add((dst, port))
        if ext:
            self.proc_ext_dsts[proc].add(dst)
            self.proc_ext_ports[proc].add(port)
            self.host_proc_ext_dsts[(src, proc)].add(dst)
            self.host_proc_ext_ports[(src, proc)].add(port)

        self.proc_dst_hosts[(proc, dst)].add(src)
        self.proc_dst_count[(proc, dst)] += 1
        self.proc_pair_count[(proc, dst, port)] += 1
        self.host_proc_dsts[(src, proc)].add(dst)
        self.host_proc_pairs[(src, proc)].add((dst, port))
        self.host_proc_count[(src, proc)] += 1
        if ext:
            self.host_proc_ext_count[(src, proc)] += 1

        self.host_ts[src].append(f.ts)


# ============================================================
# RULE FUSION
# ============================================================
def rule_scores(X: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Compute three rule scores from feature matrix X.
    Returns: (pivot, fanout, c2) each shape (n_samples,)
    """
    ix = FEATURE_INDEX
    ext_nov = X[:, ix['ext_host_proc_dst_novel']]
    proc_ratio = X[:, ix['ext_proc_ratio']]
    proc_ct = X[:, ix['ext_proc_ext_count_log']]
    proc_rar = X[:, ix['process_rarity']]
    user = X[:, ix['process_user_writable']]
    port_rar = X[:, ix['port_rarity']]
    src_fan = X[:, ix['ext_src_fanout_log']]
    src_new = X[:, ix['ext_src_new_ratio']]
    dst_fan = X[:, ix['ext_dst_host_fanout_log']]
    proc_hosts = X[:, ix['ext_proc_host_fanout_log']]
    name_len = X[:, ix['process_name_len']]
    host_proc_ratio = X[:, ix['ext_host_proc_ext_ratio']]

    # Pivot: a usually-local process on this host starts talking to a new external dst
    pivot = ext_nov * (1.0 - np.clip(proc_ratio, 0, 1)) * np.log1p(np.exp(proc_ct))

    # Fanout: rare/user-writable process talks to many external dsts on a rare port
    fanout = src_fan * port_rar * (0.5 + user) * proc_rar

    # C2 fan-in: external dst seen from many hosts, contacted by a process with low external ratio
    c2 = dst_fan * (1.0 - np.clip(proc_ratio, 0, 1)) * np.log1p(np.exp(proc_hosts))

    return pivot, fanout, c2


# ============================================================
# HIGH-LEVEL DETECTOR
# ============================================================
@dataclass
class HighLevelDetector:
    """
    High-level network anomaly detector (candidate for shadow deployment).

    Components:
    - Isolation Forest (unsupervised, trained on benign background only)
    - Rule fusion (pivot, fanout, C2-fanin) with explicit evidence
    - Isotonic calibration on local benign data
    - Operating threshold selected on local benign quantile (e.g., 99.5th)
    """
    iforest: IsolationForest | None = None
    calibrator: IsotonicRegression | None = None
    threshold: float = 0.0
    threshold_quantile: float = 0.995
    feature_version: int = FEATURE_VERSION
    trained_at: str | None = None
    training_manifest: dict[str, Any] = field(default_factory=dict)
    _rule_norm: dict | None = field(default=None, repr=False)

    def __post_init__(self):
        if self.iforest is None:
            self.iforest = IsolationForest(
                n_estimators=300,
                max_samples=4096,
                contamination='auto',
                random_state=42,
                n_jobs=8,
            )

    def fit(self, X_benign: np.ndarray, X_local: np.ndarray | None = None):
        """
        Train on benign background (X_benign) and calibrate threshold on local benign (X_local).
        """
        logger.info(f"Training IsolationForest on {len(X_benign)} benign samples")
        self.iforest.fit(X_benign)

        # Compute rule normalization parameters from LOCAL benign data (log1p space, q01-q99)
        # This ensures normalization matches the threshold selection domain
        if X_local is not None and len(X_local) > 0:
            pivot_L, fanout_L, c2_L = rule_scores(X_local)
            self._rule_norm = {
                'pivot': {'q01': float(np.quantile(np.log1p(np.maximum(pivot_L, 0)), 0.01)), 
                          'q99': float(np.quantile(np.log1p(np.maximum(pivot_L, 0)), 0.99))},
                'fanout': {'q01': float(np.quantile(np.log1p(np.maximum(fanout_L, 0)), 0.01)), 
                           'q99': float(np.quantile(np.log1p(np.maximum(fanout_L, 0)), 0.99))},
                'c2': {'q01': float(np.quantile(np.log1p(np.maximum(c2_L, 0)), 0.01)), 
                       'q99': float(np.quantile(np.log1p(np.maximum(c2_L, 0)), 0.99))},
            }
            logger.info(f"Rule norm params from LOCAL benign (log1p q01-q99): {self._rule_norm}")
        else:
            # Fallback: use benign background
            pivot_bg, fanout_bg, c2_bg = rule_scores(X_benign)
            self._rule_norm = {
                'pivot': {'q01': float(np.quantile(np.log1p(np.maximum(pivot_bg, 0)), 0.01)), 
                          'q99': float(np.quantile(np.log1p(np.maximum(pivot_bg, 0)), 0.99))},
                'fanout': {'q01': float(np.quantile(np.log1p(np.maximum(fanout_bg, 0)), 0.01)), 
                           'q99': float(np.quantile(np.log1p(np.maximum(fanout_bg, 0)), 0.99))},
                'c2': {'q01': float(np.quantile(np.log1p(np.maximum(c2_bg, 0)), 0.01)), 
                       'q99': float(np.quantile(np.log1p(np.maximum(c2_bg, 0)), 0.99))},
            }
            logger.warning(f"No local benign; rule norms from background: {self._rule_norm}")

        # Calibration: fit isotonic regression on local benign if available
        if X_local is not None and len(X_local) > 50:
            local_scores = -self.iforest.decision_function(X_local)
            # Isotonic expects increasing function; we want higher score = more anomalous
            # Map scores to [0,1] via rank, then fit isotonic to preserve order
            ranks = np.argsort(np.argsort(local_scores)) / max(1, len(local_scores) - 1)
            self.calibrator = IsotonicRegression(out_of_bounds='clip')
            self.calibrator.fit(local_scores, ranks)
            logger.info(f"Fitted isotonic calibrator on {len(X_local)} local benign flows")

        # Threshold selection on local benign using FUSED score (not just IF)
        if X_local is not None and len(X_local) > 0:
            local_fused = self.fused_score(X_local)
            self.threshold = float(np.quantile(local_fused, self.threshold_quantile))
            logger.info(f"Threshold set at local benign fused q{self.threshold_quantile:.3f} = {self.threshold:.6f}")
        else:
            # Fallback: use benign background fused quantile
            bg_fused = self.fused_score(X_benign)
            self.threshold = float(np.quantile(bg_fused, self.threshold_quantile))
            logger.warning(f"No local benign data; threshold from background fused q{self.threshold_quantile:.3f} = {self.threshold:.6f}")

        self.trained_at = datetime.now(UTC).isoformat()
        self.training_manifest = {
            'n_benign_train': len(X_benign),
            'n_local_calibrate': len(X_local) if X_local is not None else 0,
            'threshold_quantile': self.threshold_quantile,
            'threshold': self.threshold,
            'feature_version': self.feature_version,
            'iforest_params': self.iforest.get_params(),
            'rule_norm': self._rule_norm,
        }

    def _raw_anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Raw IF anomaly score (higher = more anomalous)."""
        return -self.iforest.decision_function(X)

    def score_batch(self, X: np.ndarray) -> np.ndarray:
        """Calibrated anomaly score in [0, 1]."""
        raw = self._raw_anomaly_score(X)
        if self.calibrator is not None:
            return np.clip(self.calibrator.predict(raw), 0.0, 1.0)
        # Fallback: min-max normalize on training benign (not ideal)
        return np.clip((raw - raw.min()) / max(1e-9, raw.max() - raw.min()), 0.0, 1.0)

    def rule_scores(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Return (pivot, fanout, c2) rule scores."""
        return rule_scores(X)

    def fused_score(self, X: np.ndarray) -> np.ndarray:
        """
        Fused score: max of (IF component, rule components).
        
        This allows any single strong signal (IF or a rule) to produce a high score.
        Threshold is set on local benign fused scores at the configured quantile.
        """
        if_score = self.score_batch(X)
        pivot, fanout, c2 = self.rule_scores(X)
        
        # Normalize rules using local benign stats
        if hasattr(self, '_rule_norm') and self._rule_norm is not None:
            pivot_norm = self._normalize_rule(pivot, self._rule_norm['pivot'])
            fanout_norm = self._normalize_rule(fanout, self._rule_norm['fanout'])
            c2_norm = self._normalize_rule(c2, self._rule_norm['c2'])
        else:
            def norm(z):
                z = np.log1p(np.maximum(z, 0))
                return np.clip((z - z.min()) / max(1e-9, z.max() - z.min()), 0.0, 1.0)
            pivot_norm = norm(pivot)
            fanout_norm = norm(fanout)
            c2_norm = norm(c2)
        
        # Max of rule scores (any single rule can drive the score)
        rule_max = np.maximum(np.maximum(pivot_norm, fanout_norm), c2_norm)
        
        # Fused = max of IF contribution and rule contribution
        # This allows either strong IF OR strong rule to trigger
        return np.maximum(0.4 * if_score, 0.6 * rule_max)
    
    def _normalize_rule(self, z: np.ndarray, params: dict) -> np.ndarray:
        """Normalize rule score using stored training parameters (log1p space).
        
        No clipping at 1.0 - allows attack scores to exceed benign maximum.
        """
        z = np.log1p(np.maximum(z, 0))
        q01 = params.get('q01', 0.0)
        q99 = params.get('q99', 1.0)
        if q99 <= q01:
            q99 = q01 + 1.0
        # No upper clip - attacks can exceed benign q99
        return np.maximum((z - q01) / (q99 - q01), 0.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Binary decision at operating threshold."""
        return (self.fused_score(X) >= self.threshold).astype(int)

    def score_with_evidence(self, X: np.ndarray) -> list[dict]:
        """Score with per-sample evidence breakdown."""
        if_scores = self.score_batch(X)
        pivot, fanout, c2 = self.rule_scores(X)
        fused = self.fused_score(X)
        decisions = fused >= self.threshold
        out = []
        for i in range(len(X)):
            out.append({
                'fused_score': float(fused[i]),
                'if_score': float(if_scores[i]),
                'pivot_score': float(pivot[i]),
                'fanout_score': float(fanout[i]),
                'c2_score': float(c2[i]),
                'is_anomaly': bool(decisions[i]),
                'threshold': self.threshold,
                'evidence': {
                    'pivot': float(pivot[i]),
                    'fanout': float(fanout[i]),
                    'c2_fanin': float(c2[i]),
                },
            })
        return out

    def save(self, path: Path):
        """Persist detector to disk."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            'iforest': self.iforest,
            'calibrator': self.calibrator,
            'threshold': self.threshold,
            'threshold_quantile': self.threshold_quantile,
            'feature_version': self.feature_version,
            'trained_at': self.trained_at,
            'training_manifest': self.training_manifest,
            'features': FEATURES,
            'feature_version': FEATURE_VERSION,
            '_rule_norm': self._rule_norm,
        }
        joblib.dump(bundle, path)
        logger.info(f"Saved high-level detector to {path}")

    @classmethod
    def load(cls, path: Path) -> 'HighLevelDetector':
        """Load detector from disk."""
        bundle = joblib.load(path)
        det = cls(
            iforest=bundle.get('iforest'),
            calibrator=bundle.get('calibrator'),
            threshold=bundle.get('threshold', 0.0),
            threshold_quantile=bundle.get('threshold_quantile', 0.995),
            feature_version=bundle.get('feature_version', FEATURE_VERSION),
            trained_at=bundle.get('trained_at'),
            training_manifest=bundle.get('training_manifest', {}),
            _rule_norm=bundle.get('_rule_norm'),
        )
        # Verify feature version
        if bundle.get('feature_version') != FEATURE_VERSION:
            logger.warning(f"Feature version mismatch: bundle={bundle.get('feature_version')}, current={FEATURE_VERSION}")
        return det


# ============================================================
# LIVE SCORING INTEGRATION
# ============================================================
def _flow_from_conn(conn: NetworkConnection) -> Flow:
    """Convert NetworkConnection ORM row to Flow."""
    return Flow(
        ts=conn.observed_at.timestamp() if conn.observed_at else 0.0,
        src=conn.local_ip or '',
        dst=conn.remote_ip or '',
        port=conn.remote_port or 0,
        process=conn.process or '',
        domain='',  # Not available in NetworkConnection
        service='',
        state=conn.state or '',
        bsent=conn.bytes_sent or 0,
        brecv=conn.bytes_recv or 0,
        duration=conn.duration_seconds or 0.0,
    )


def score_network_connections(
    detector: HighLevelDetector,
    hours: int = 1,
    session=None
) -> tuple[int, int]:
    """
    Score recent network connections in SHADOW mode.
    Persists MLShadowScore rows; does NOT mutate events.
    Returns: (scored_count, flagged_count)
    """
    from backend.ml.deployment import get_deployment_mode
    if get_deployment_mode() == 'off':
        return 0, 0

    session = session or SessionLocal()
    try:
        since = datetime.now(UTC) - pd.Timedelta(hours=hours)
        conns = session.query(NetworkConnection).filter(
            NetworkConnection.observed_at >= since
        ).all()

        if not conns:
            return 0, 0

        profiler = Profiler()
        X = np.zeros((len(conns), N_FEATURES), dtype=np.float32)
        for i, conn in enumerate(conns):
            f = _flow_from_conn(conn)
            X[i] = profiler.features(f)
            profiler.update(f)

        results = detector.score_with_evidence(X)
        scored = 0
        flagged = 0
        for conn, res in zip(conns, results):
            shadow = MLShadowScore(
                connection_id=conn.id,
                observed_at=conn.observed_at,
                model_version=detector.training_manifest.get('version', 'high_level_v1'),
                feature_version=detector.feature_version,
                fused_score=res['fused_score'],
                if_score=res['if_score'],
                pivot_score=res['pivot_score'],
                fanout_score=res['fanout_score'],
                c2_score=res['c2_score'],
                is_anomaly=res['is_anomaly'],
                threshold=res['threshold'],
                evidence_json=json.dumps(res['evidence']),
            )
            session.add(shadow)
            scored += 1
            if res['is_anomaly']:
                flagged += 1

        session.commit()
        logger.info(f"High-level shadow scoring: {scored} connections, {flagged} flagged")
        return scored, flagged
    finally:
        session.close()


# ============================================================
# BENCHMARK HELPERS
# ============================================================
def build_feature_matrix(meta: pd.DataFrame) -> np.ndarray:
    """Build feature matrix from benchmark meta DataFrame (offline, sorted by time)."""
    meta = meta.sort_values('ts').reset_index(drop=True)
    profiler = Profiler()
    X = np.zeros((len(meta), N_FEATURES), dtype=np.float32)
    for i, r in enumerate(meta.itertuples(index=False)):
        f = Flow(
            ts=pd.Timestamp(r.ts).timestamp(),
            src=str(r.host or ''),
            dst=str(r.dst_ip or ''),
            port=int(r.dst_port or 0),
            process=str(r.image or ''),
            domain=str(r.dst_host or ''),
        )
        X[i] = profiler.features(f)
        profiler.update(f)
    return X


def build_local_matrix(local_csv: Path) -> np.ndarray:
    """Build feature matrix from local_flows.csv."""
    df = pd.read_csv(local_csv)
    df['observed_at'] = pd.to_datetime(df['observed_at'], utc=True)
    df = df.sort_values('observed_at').reset_index(drop=True)
    profiler = Profiler()
    X = np.zeros((len(df), N_FEATURES), dtype=np.float32)
    for i, r in enumerate(df.itertuples(index=False)):
        f = Flow(
            ts=pd.Timestamp(r.observed_at).timestamp(),
            src=str(r.local_ip or ''),
            dst=str(r.remote_ip or ''),
            port=int(r.remote_port or 0),
            process=str(r.process or ''),
            state=str(r.state or ''),
        )
        X[i] = profiler.features(f)
        profiler.update(f)
    return X


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) > 1 and sys.argv[1] == 'build':
        # Build benchmark matrices
        meta = pd.read_pickle('/home/haaraphel/BARAQ/datasets/botsv1_bench/meta.pkl')
        X = build_feature_matrix(meta)
        np.save('/home/haaraphel/BARAQ/datasets/botsv1_bench/X_hl.npy', X)
        print(f"Saved X_hl.npy: {X.shape}")

        X_local = build_local_matrix(Path('/home/haaraphel/BARAQ/datasets/botsv1_bench/local_flows.csv'))
        np.save('/home/haaraphel/BARAQ/datasets/botsv1_bench/local_X_hl.npy', X_local)
        print(f"Saved local_X_hl.npy: {X_local.shape}")

    elif len(sys.argv) > 1 and sys.argv[1] == 'train':
        # Train detector
        X = np.load('/home/haaraphel/BARAQ/datasets/botsv1_bench/X_hl.npy')
        meta = pd.read_pickle('/home/haaraphel/BARAQ/datasets/botsv1_bench/meta.pkl')
        bg_mask = ((meta.dataset == 'botsv1') & (meta.label == 0)).to_numpy()
        local_mask = (meta.dataset == 'local').to_numpy()

        rng = np.random.default_rng(0)
        bg_idx = np.where(bg_mask)[0]
        rng.shuffle(bg_idx)
        train_idx = bg_idx[:60000]

        X_local = np.load('/home/haaraphel/BARAQ/datasets/botsv1_bench/local_X_hl.npy')

        det = HighLevelDetector()
        det.fit(X[train_idx], X_local)
        det.save(Path('/home/haaraphel/BARAQ/datasets/botsv1_bench/high_level_detector.joblib'))
        print(f"Trained detector, threshold={det.threshold:.6f}")

    elif len(sys.argv) > 1 and sys.argv[1] == 'eval':
        # Quick evaluation
        det = HighLevelDetector.load(Path('/home/haaraphel/BARAQ/datasets/botsv1_bench/high_level_detector.joblib'))
        X = np.load('/home/haaraphel/BARAQ/datasets/botsv1_bench/X_hl.npy')
        meta = pd.read_pickle('/home/haaraphel/BARAQ/datasets/botsv1_bench/meta.pkl')
        for camp in ['A', 'B']:
            mask = (meta.campaign == camp).to_numpy()
            scores = det.fused_score(X[mask])
            recall = (scores >= det.threshold).mean()
            print(f"Campaign {camp}: n={mask.sum()}, recall@{det.threshold:.4f}={recall:.4f}")
        X_local = np.load('/home/haaraphel/BARAQ/datasets/botsv1_bench/local_X_hl.npy')
        local_scores = det.fused_score(X_local)
        fpr = (local_scores >= det.threshold).mean()
        print(f"Local FPR: {fpr:.4f}")

    else:
        print("Usage: python -m backend.ml.high_level [build|train|eval]")