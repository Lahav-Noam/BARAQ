#!/usr/bin/env python3
"""RESEARCH ONLY - REJECTED FOR DEPLOYMENT.

The S2 context result was a dataset artifact: local rows have no process path,
BOTSv1 rows do, and a single path feature (`image_entropy`/`image_len`) learns
Campaign B's GUID-style AppData path.  Removing path/image columns collapses
S2 B recall from 48,197/48,199 to 1/48,199.  See section 8.7 of
``docs/botsv1-ml-benchmark.md``.  Do not integrate these features into the live
feature builder or use this matrix for promotion.

Add causal process/destination-context features to the BOTSv1 matrix.

The original 29-feature network matrix is per-event and ignores the process
path and the history of what that process normally talks to.  Campaign A is a
served PHP binary that normally talks only to localhost:3306, then starts
talking to a public C2 address.  Campaign B is a new executable in a user
writable directory that fans out to thousands of destinations.  Both are
visible in process/destination *context*, not in a single packet.

Every feature here is computed from strictly earlier events (the rows are in
timestamp order), so the matrix can be used with time-forward and campaign
hold-outs without train/test leakage.  It deliberately does not use labels,
campaign names, host names, or destination IP values as features.

Output: ``datasets/botsv1_bench/features_context.npz`` containing the original
matrix plus the context columns, feature names, and a feature-set version.

Run:
    PYTHONPATH=. .venv/bin/python scripts/bench_botsv1_context_features.py
"""
from __future__ import annotations

import argparse
import math
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path("datasets/botsv1_bench")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _is_private(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                          "172.19.", "172.2", "172.3", "127.", "169.254."))


def _is_public(ip: str) -> bool:
    if not ip:
        return False
    return not _is_private(ip) and not ip.startswith(("224.", "239.", "255.",
                                                      "0."))


def _path_flags(path: str) -> list[float]:
    p = path.lower().replace("/", "\\")
    return [
        1.0 if "\\appdata\\" in p else 0.0,
        1.0 if any(x in p for x in ("\\temp\\", "\\tmp\\", "\\downloads\\")) else 0.0,
        1.0 if "\\users\\" in p else 0.0,
        1.0 if "\\public\\" in p else 0.0,
        1.0 if "\\windows\\system32\\" in p or "\\windows\\syswow64\\" in p else 0.0,
        1.0 if "\\windows\\" in p else 0.0,
        1.0 if "\\program files" in p else 0.0,
        1.0 if "\\inetpub\\" in p or "\\wwwroot\\" in p else 0.0,
        1.0 if not p else 0.0,
    ]


def _hostname_flags(host: str) -> list[float]:
    h = (host or "").strip().lower()
    if not h:
        return [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    digits = sum(c.isdigit() for c in h)
    return [
        0.0,
        min(len(h) / 80.0, 1.0),
        _entropy(h) / 7.0,
        min(digits / max(len(h), 1), 1.0),
        min(h.count("-") / 8.0, 1.0),
        min(h.count(".") / 8.0, 1.0),
        1.0 if h.endswith((".xyz", ".top", ".click", ".work", ".support",
                           ".review", ".country", ".stream")) else 0.0,
        min(len(h) / max(h.count(".") + 1, 1) / 20.0, 1.0),
    ]


def build(meta: pd.DataFrame, base_X: np.ndarray) -> tuple[np.ndarray, list[str]]:
    meta = meta.copy()
    meta["ts"] = pd.to_datetime(meta["ts"], utc=True)
    meta = meta.sort_values("ts", kind="mergesort").reset_index(drop=True)
    # The caller passes base_X aligned to the original frame; reorder it with
    # the same stable sort so every row still matches its metadata.
    base_X = np.asarray(base_X, dtype=float)
    base_names = [
        "net_event_type", "is_network_event", "is_login_event", "is_process_event",
        "hour_sin", "hour_cos", "is_night", "is_weekend", "src_ip_num", "dst_ip_num",
        "is_private_src", "is_private_dst", "is_link_local_dst", "is_multicast_dst",
        "is_loopback_src", "dst_port_norm", "port_category", "time_since_dst",
        "time_since_src", "conn_count_100", "src_count_100", "is_attack_ip",
        "is_attack_src", "time_since_scaled", "rapid_repeat", "conn_count_50",
        "src_count_50", "same_src_dst", "dst_without_src",
    ]
    if base_X.shape[1] != len(base_names):
        raise ValueError(f"expected {len(base_names)} base features, got {base_X.shape[1]}")

    context_names = [
        # process novelty / history
        "proc_seen_log", "proc_is_new", "proc_unique_ip_log",
        "proc_unique_port_log", "proc_public_seen_log", "proc_public_ip_new",
        "proc_public_ratio", "proc_private_ratio", "proc_loopback_ratio",
        # process -> destination affinity
        "proc_dst_ip_seen_log", "proc_dst_ip_new", "proc_dst_port_seen_log",
        "proc_dst_port_new", "proc_dst_host_seen_log", "proc_dst_host_new",
        # source host fan-out
        "host_seen_log", "host_unique_ip_log", "host_unique_port_log",
        "host_unique_proc_log", "host_public_ratio",
        # destination fan-in
        "dst_ip_seen_log", "dst_fanin_log", "dst_proc_fanin_log",
        "dst_port_seen_log", "dst_port_rare",
        # destination / path / name shape
        "dst_is_public", "dst_is_private", "dst_is_loopback",
        "path_appdata", "path_temp_download", "path_users", "path_public",
        "path_system32", "path_windows", "path_program_files", "path_webroot",
        "path_missing", "image_len", "image_entropy", "image_digits",
        "hostname_missing", "hostname_len", "hostname_entropy",
        "hostname_digit_ratio", "hostname_hyphens", "hostname_dots",
        "hostname_susp_tld", "hostname_label_len",
    ]

    # Cumulative state.  The value read for a row is the state *before* the
    # row, then the row is folded in.
    proc_count: dict[str, int] = defaultdict(int)
    proc_ips: dict[str, set[str]] = defaultdict(set)
    proc_ports: dict[str, set[int]] = defaultdict(set)
    proc_public: dict[str, int] = defaultdict(int)
    proc_private: dict[str, int] = defaultdict(int)
    proc_loopback: dict[str, int] = defaultdict(int)
    proc_public_ips: dict[str, set[str]] = defaultdict(set)
    proc_dst_ip: dict[tuple[str, str], int] = defaultdict(int)
    proc_dst_port: dict[tuple[str, int], int] = defaultdict(int)
    proc_dst_host: dict[tuple[str, str], int] = defaultdict(int)

    host_count: dict[str, int] = defaultdict(int)
    host_ips: dict[str, set[str]] = defaultdict(set)
    host_ports: dict[str, set[int]] = defaultdict(set)
    host_procs: dict[str, set[str]] = defaultdict(set)
    host_public: dict[str, int] = defaultdict(int)

    dst_count: dict[str, int] = defaultdict(int)
    dst_hosts: dict[str, set[str]] = defaultdict(set)
    dst_procs: dict[str, set[str]] = defaultdict(set)
    port_count: dict[int, int] = defaultdict(int)
    total = 0

    rows: list[list[float]] = []
    for r in meta.itertuples(index=False):
        ip = str(r.dst_ip or "")
        host = str(r.host or "")
        image = str(r.image or "")
        proc = image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower() or "unknown"
        port = int(r.dst_port or 0)
        dst_host = str(r.dst_host or "").lower()
        public = _is_public(ip)
        private = _is_private(ip)
        loopback = ip in ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1")

        hc = host_count[host]
        h_ips = host_ips[host]
        h_ports = host_ports[host]
        h_procs = host_procs[host]
        hp = host_public[host]
        pc = proc_count[proc]
        p_ips = proc_ips[proc]
        p_ports = proc_ports[proc]
        ppub = proc_public[proc]
        ppriv = proc_private[proc]
        ploop = proc_loopback[proc]
        publ_ips = proc_public_ips[proc]
        pd_ip = proc_dst_ip[(proc, ip)]
        pd_port = proc_dst_port[(proc, port)]
        pd_host = proc_dst_host[(proc, dst_host)]
        dc = dst_count[ip]
        d_hosts = dst_hosts[ip]
        d_procs = dst_procs[ip]
        port_seen = port_count[port]

        pathf = _path_flags(image)
        hostf = _hostname_flags(dst_host)
        rows.append([
            math.log1p(pc), 1.0 if pc == 0 else 0.0,
            math.log1p(len(p_ips)), math.log1p(len(p_ports)),
            math.log1p(ppub), 1.0 if public and ip not in publ_ips else 0.0,
            ppub / max(pc, 1), ppriv / max(pc, 1), ploop / max(pc, 1),
            math.log1p(pd_ip), 1.0 if pd_ip == 0 else 0.0,
            math.log1p(pd_port), 1.0 if pd_port == 0 else 0.0,
            math.log1p(pd_host), 1.0 if pd_host == 0 and dst_host else 0.0,
            math.log1p(hc), math.log1p(len(h_ips)), math.log1p(len(h_ports)),
            math.log1p(len(h_procs)), hp / max(hc, 1),
            math.log1p(dc), math.log1p(len(d_hosts)), math.log1p(len(d_procs)),
            math.log1p(port_seen), 1.0 if total and port_seen == 0 else 0.0,
            1.0 if public else 0.0, 1.0 if private else 0.0,
            1.0 if loopback else 0.0,
            *pathf,
            min(len(image) / 120.0, 1.0), _entropy(image) / 7.0,
            min(sum(c.isdigit() for c in image) / max(len(image), 1), 1.0),
            *hostf,
        ])

        # Fold this row into the causal state.
        proc_count[proc] += 1
        proc_ips[proc].add(ip)
        proc_ports[proc].add(port)
        if public:
            proc_public[proc] += 1
            proc_public_ips[proc].add(ip)
        elif private:
            proc_private[proc] += 1
        elif loopback:
            proc_loopback[proc] += 1
        proc_dst_ip[(proc, ip)] += 1
        proc_dst_port[(proc, port)] += 1
        proc_dst_host[(proc, dst_host)] += 1

        host_count[host] += 1
        host_ips[host].add(ip)
        host_ports[host].add(port)
        host_procs[host].add(proc)
        if public:
            host_public[host] += 1

        dst_count[ip] += 1
        dst_hosts[ip].add(host)
        dst_procs[ip].add(proc)
        port_count[port] += 1
        total += 1

    names = base_names + context_names
    X = np.column_stack([base_X, np.asarray(rows, dtype=float)])
    if X.shape[1] != len(names):
        raise ValueError(f"feature count mismatch: {X.shape[1]} cols, {len(names)} names")
    return X, names


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "features_context.npz"))
    args = ap.parse_args()
    d = np.load(ROOT / "features.npz", allow_pickle=True)
    meta = pd.read_pickle(ROOT / "meta.pkl")
    X, names = build(meta, d["X"])
    np.savez_compressed(args.out, X=X, y=d["y"], names=np.asarray(names),
                        feature_set="network_context_v1")
    print(f"wrote {args.out}: {X.shape[0]:,} x {X.shape[1]} "
          f"({len(names) - 29} context features)")
    print("context features:", ", ".join(names[29:]))


if __name__ == "__main__":
    main()
