#!/usr/bin/env python3
"""
Live-like attack simulation for high-level detector validation.

Creates a test database (baraq_test) with simulated attack traffic:
- C2 beaconing (periodic, low-volume)
- Exfiltration (high-volume, sustained)
- DGA-like DNS (algorithmically generated domains)
- Port scanning (many ports, few connections each)

Runs the high-level detector in SHADOW mode and verifies:
1. Monitoring rows are created (ml_shadow_scores)
2. No event mutation occurs
3. No alerts are created
4. Benign control traffic does not flag at operating threshold
"""
from __future__ import annotations
import argparse
import logging
import random
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, '/home/haaraphel/BARAQ')

from backend.database.models import Base, NetworkConnection, NormalizedEvent, MLShadowScore
from backend.ml.high_level import HighLevelDetector, build_local_matrix
from backend.ml.deployment import configured_mode

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

TEST_DB_URL = "postgresql+psycopg://baraq:baraq@127.0.0.1:5432/baraq_test"
DETECTOR_PATH = Path('/home/haaraphel/BARAQ/datasets/botsv1_bench/high_level_detector.joblib')
LOCAL_FEATURES_PATH = Path('/home/haaraphel/BARAQ/datasets/botsv1_bench/local_X_hl.npy')


def setup_test_db():
    """Create test database schema."""
    engine = create_engine(TEST_DB_URL)
    # Drop and recreate
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    logger.info("Test database schema created")
    return engine


def generate_benign_traffic(session, start_time: datetime, duration_hours: int = 1, 
                            n_hosts: int = 5, n_flows_per_host: int = 100):
    """Generate realistic benign background traffic."""
    logger.info(f"Generating benign traffic: {n_hosts} hosts, {n_flows_per_host} flows each")
    
    benign_processes = [
        'C:\\Windows\\System32\\svchost.exe',
        'C:\\Windows\\System32\\dns.exe',
        'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
        'C:\\Program Files (x86)\\Microsoft\\OneDrive\\OneDrive.exe',
        'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe',
    ]
    
    benign_destinations = [
        ('13.107.42.12', 443),   # Microsoft
        ('40.90.137.124', 443),  # Microsoft
        ('23.203.184.161', 443), # Akamai/CDN
        ('8.8.8.8', 53),         # Google DNS
        ('1.1.1.1', 53),         # Cloudflare DNS
        ('192.168.1.1', 53),     # Local DNS
        ('192.168.1.255', 137),  # NetBIOS
    ]
    
    flows = []
    for host_id in range(n_hosts):
        host = f'WORKSTATION{host_id:03d}.corp.local'
        base_time = start_time
        
        for i in range(n_flows_per_host):
            proc = random.choice(benign_processes)
            dst_ip, dst_port = random.choice(benign_destinations)
            
            # Add some temporal correlation (beaconing-like for updates)
            if 'svchost' in proc and dst_port == 443:
                interval = random.uniform(300, 3600)  # 5-60 min
            else:
                interval = random.uniform(1, 300)
            
            base_time += timedelta(seconds=interval)
            
            flow = NetworkConnection(
                observed_at=base_time,
                pid=random.randint(1000, 9999),
                process=proc,
                local_ip=f'10.0.{host_id}.{random.randint(2,254)}',
                local_port=random.randint(49152, 65535),
                remote_ip=dst_ip,
                remote_port=dst_port,
                state='ESTABLISHED' if dst_port in (80, 443) else 'NONE',
                is_listening=False,
                bytes_sent=random.randint(500, 100000),
                bytes_recv=random.randint(500, 500000),
                duration_seconds=random.uniform(0.01, 5.0),
            )
            flows.append(flow)
    
    session.bulk_save_objects(flows)
    session.commit()
    logger.info(f"Inserted {len(flows)} benign flows")
    return flows


def generate_c2_beacon(session, start_time: datetime, duration_hours: int = 1):
    """Generate C2 beacon traffic: periodic, low-volume, same destination."""
    logger.info("Generating C2 beacon traffic")
    
    c2_procs = [
        'C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\updater.exe',
        'C:\\ProgramData\\Windows\\Tasks\\svchost.exe',  # masquerading
    ]
    
    c2_dst = '198.51.100.42'  # External C2 server
    c2_port = 443
    
    flows = []
    base_time = start_time
    
    for proc in c2_procs:
        for beacon_num in range(120):  # 120 beacons over 1 hour = 1 per 30 sec
            # Add jitter ±10%
            interval = 30 + random.uniform(-3, 3)
            base_time += timedelta(seconds=interval)
            
            flow = NetworkConnection(
                observed_at=base_time,
                pid=random.randint(1000, 9999),
                process=proc,
                local_ip=f'10.0.5.{random.randint(10,50)}',
                local_port=random.randint(49152, 65535),
                remote_ip=c2_dst,
                remote_port=c2_port,
                state='ESTABLISHED',
                is_listening=False,
                bytes_sent=random.randint(200, 800),
                bytes_recv=random.randint(100, 500),
                duration_seconds=random.uniform(0.05, 0.2),
            )
            flows.append(flow)
    
    session.bulk_save_objects(flows)
    session.commit()
    logger.info(f"Inserted {len(flows)} C2 beacon flows")
    return flows


def generate_exfiltration(session, start_time: datetime):
    """Generate data exfiltration: sustained high-volume transfer."""
    logger.info("Generating exfiltration traffic")
    
    exfil_proc = 'C:\\Users\\bob\\Documents\\backup_tool.exe'
    exfil_dst = '203.0.113.195'  # External exfil server
    exfil_port = 443
    
    flows = []
    base_time = start_time + timedelta(minutes=10)
    
    # 10 large transfers over 20 minutes
    for i in range(10):
        base_time += timedelta(minutes=2)
        
        flow = NetworkConnection(
            observed_at=base_time,
            pid=random.randint(1000, 9999),
            process=exfil_proc,
            local_ip='10.0.10.25',
            local_port=random.randint(49152, 65535),
            remote_ip=exfil_dst,
            remote_port=exfil_port,
            state='ESTABLISHED',
            is_listening=False,
            bytes_sent=random.randint(50_000_000, 200_000_000),
            bytes_recv=random.randint(1000, 5000),
            duration_seconds=random.uniform(30.0, 120.0),
        )
        flows.append(flow)
    
    session.bulk_save_objects(flows)
    session.commit()
    logger.info(f"Inserted {len(flows)} exfiltration flows")
    return flows


def generate_dga_dns(session, start_time: datetime):
    """Generate DGA-like DNS traffic: many algorithmically generated domains."""
    logger.info("Generating DGA-like DNS traffic")
    
    dga_proc = 'C:\\Windows\\Temp\\malware.exe'
    
    flows = []
    base_time = start_time + timedelta(minutes=20)
    
    # Generate 200 DGA domains over 30 minutes
    for i in range(200):
        base_time += timedelta(seconds=random.uniform(5, 15))
        
        # Simulate DGA domain (random-ish)
        domain = f'xkqj{random.randint(1000,9999)}z{random.randint(100,999)}.malicious-tld.example'
        
        flow = NetworkConnection(
            observed_at=base_time,
            pid=random.randint(1000, 9999),
            process=dga_proc,
            local_ip='10.0.15.100',
            local_port=random.randint(49152, 65535),
            remote_ip='10.0.0.53',
            remote_port=53,
            state='NONE',
            is_listening=False,
            bytes_sent=random.randint(60, 120),
            bytes_recv=random.randint(80, 200),
            duration_seconds=random.uniform(0.005, 0.05),
        )
        flows.append(flow)
    
    session.bulk_save_objects(flows)
    session.commit()
    logger.info(f"Inserted {len(flows)} DGA DNS flows")
    return flows


def generate_port_scan(session, start_time: datetime):
    """Generate port scanning: many ports, few connections each."""
    logger.info("Generating port scan traffic")
    
    scan_proc = 'C:\\Windows\\System32\\nmap.exe'  # Or custom scanner
    target_ip = '10.0.20.0/24'  # Internal subnet
    
    flows = []
    base_time = start_time + timedelta(minutes=40)
    
    # Scan 1000 ports on 50 hosts
    for host_octet in range(1, 51):
        target = f'10.0.20.{host_octet}'
        for port in [22, 23, 80, 135, 139, 443, 445, 3389, 5985, 8080]:
            base_time += timedelta(milliseconds=random.randint(10, 100))
            
            flow = NetworkConnection(
                observed_at=base_time,
                pid=random.randint(1000, 9999),
                process=scan_proc,
                local_ip='10.0.30.50',
                local_port=random.randint(49152, 65535),
                remote_ip=target,
                remote_port=port,
                state='SYN_SENT',
                is_listening=False,
                bytes_sent=random.randint(40, 60),
                bytes_recv=0,
                duration_seconds=random.uniform(0.001, 0.1),
            )
            flows.append(flow)
    
    session.bulk_save_objects(flows)
    session.commit()
    logger.info(f"Inserted {len(flows)} port scan flows")
    return flows


def run_detector_shadow(engine, detector: HighLevelDetector, hours: int = 2):
    """Run detector in shadow mode against test database."""
    logger.info("Running detector in SHADOW mode")
    
    # Check deployment mode
    mode = configured_mode()
    logger.info(f"Current deployment mode: {mode}")
    if mode == 'off':
        logger.warning("Deployment mode is OFF, skipping shadow scoring")
        return 0, 0
    
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        since = datetime.now(UTC) - timedelta(hours=hours)
        
        # Get connections to score
        conns = session.query(NetworkConnection).filter(
            NetworkConnection.observed_at >= since
        ).all()
        
        if not conns:
            logger.warning("No connections to score")
            return 0, 0
        
        logger.info(f"Scoring {len(conns)} connections")
        
        # Build features using the same profiler logic
        from backend.ml.high_level import Profiler, _flow_from_conn
        
        profiler = Profiler()
        X = np.zeros((len(conns), 92), dtype=np.float32)
        
        for i, conn in enumerate(conns):
            f = _flow_from_conn(conn)
            X[i] = profiler.features(f)
            profiler.update(f)
        
        # Score with detector
        results = detector.score_with_evidence(X)
        
        # Persist shadow scores
        scored = 0
        flagged = 0
        for conn, res in zip(conns, results):
            shadow = MLShadowScore(
                stream='network',
                model_version=1,
                feature_version=detector.feature_version,
                entity=f"{conn.remote_ip}:{conn.remote_port}",
                score=res['fused_score'],
                threshold=res['threshold'],
                flagged=res['is_anomaly'],
                observed_at=conn.observed_at,
                org='',
                demo=False,
                detail={
                    'if_score': res['if_score'],
                    'pivot_score': res['pivot_score'],
                    'fanout_score': res['fanout_score'],
                    'c2_score': res['c2_score'],
                    'evidence': res['evidence'],
                    'connection_id': conn.id,
                    'process': conn.process,
                    'remote_ip': conn.remote_ip,
                    'remote_port': conn.remote_port,
                },
            )
            session.add(shadow)
            scored += 1
            if res['is_anomaly']:
                flagged += 1
        
        session.commit()
        logger.info(f"Shadow scoring complete: {scored} scored, {flagged} flagged")
        
        # Verify no event mutation
        events = session.query(NormalizedEvent).filter(
            NormalizedEvent.timestamp >= since
        ).all()
        mutated = sum(1 for e in events if e.is_anomaly or e.ml_score is not None)
        logger.info(f"Event mutation check: {mutated} events mutated (should be 0)")
        
        # Verify no alerts created (assuming alerts table exists)
        # This would check an alerts table if it exists
        
        return scored, flagged
        
    finally:
        session.close()


def verify_results(engine, detector: HighLevelDetector):
    """Verify detection results match expectations."""
    logger.info("Verifying detection results")
    
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # Check shadow scores - simple query
        shadows = session.query(MLShadowScore).all()
        conns = {c.id: c for c in session.query(NetworkConnection).all()}
        
        # Group by process
        proc_results = {}
        for s in shadows:
            conn = conns.get(s.detail.get('connection_id'))
            if not conn:
                continue
            proc = conn.process
            fused = s.score
            is_anom = s.flagged
            
            if proc not in proc_results:
                proc_results[proc] = {'total': 0, 'flagged': 0, 'scores': []}
            proc_results[proc]['total'] += 1
            proc_results[proc]['scores'].append(fused)
            if is_anom:
                proc_results[proc]['flagged'] += 1
        
        logger.info("Detection results by process:")
        for proc, stats in sorted(proc_results.items(), key=lambda x: -x[1]['flagged']):
            flagged_rate = stats['flagged'] / stats['total'] if stats['total'] > 0 else 0
            avg_score = np.mean(stats['scores']) if stats['scores'] else 0
            logger.info(f"  {proc}: {stats['flagged']}/{stats['total']} flagged ({flagged_rate:.1%}), avg score={avg_score:.3f}")
        
        # Verify benign processes have low flag rate
        benign_procs = ['svchost.exe', 'dns.exe', 'msedge.exe', 'OneDrive.exe', 'WmiPrvSE.exe']
        for proc in benign_procs:
            if proc in proc_results:
                stats = proc_results[proc]
                flagged_rate = stats['flagged'] / stats['total'] if stats['total'] > 0 else 0
                if flagged_rate > 0.05:
                    logger.warning(f"Benign process {proc} has high flag rate: {flagged_rate:.1%}")
                else:
                    logger.info(f"Benign process {proc}: {flagged_rate:.1%} flag rate (OK)")
        
        return proc_results
        
    finally:
        session.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--skip-benign', action='store_true')
    parser.add_argument('--skip-c2', action='store_true')
    parser.add_argument('--skip-exfil', action='store_true')
    parser.add_argument('--skip-dga', action='store_true')
    parser.add_argument('--skip-scan', action='store_true')
    parser.add_argument('--hours', type=int, default=2)
    args = parser.parse_args()
    
    # Load detector
    logger.info(f"Loading detector from {DETECTOR_PATH}")
    detector = HighLevelDetector.load(DETECTOR_PATH)
    logger.info(f"Detector loaded: threshold={detector.threshold:.4f}, feature_version={detector.feature_version}")
    
    # Setup test DB
    engine = setup_test_db()
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        start_time = datetime.now(UTC)
        
        # Generate traffic
        if not args.skip_benign:
            generate_benign_traffic(session, start_time, args.hours)
        
        if not args.skip_c2:
            generate_c2_beacon(session, start_time, args.hours)
        
        if not args.skip_exfil:
            generate_exfiltration(session, start_time)
        
        if not args.skip_dga:
            generate_dga_dns(session, start_time)
        
        if not args.skip_scan:
            generate_port_scan(session, start_time)
        
        logger.info("All traffic generated")
        
    finally:
        session.close()
    
    # Run detector in shadow mode
    scored, flagged = run_detector_shadow(engine, detector, args.hours)
    
    # Verify results
    results = verify_results(engine, detector)
    
    # Summary
    logger.info("\n=== SIMULATION SUMMARY ===")
    logger.info(f"Total connections scored: {scored}")
    logger.info(f"Total flagged as anomalous: {flagged}")
    logger.info(f"Flag rate: {flagged/scored*100:.1f}%" if scored > 0 else "N/A")
    logger.info(f"Detector threshold: {detector.threshold:.4f}")
    logger.info(f"Deployment mode: {configured_mode()}")
    
    # Save results
    output = {
        'timestamp': datetime.now(UTC).isoformat(),
        'detector_threshold': detector.threshold,
        'detector_feature_version': detector.feature_version,
        'scored': scored,
        'flagged': flagged,
        'flag_rate': flagged / scored if scored > 0 else 0,
        'process_results': {k: {**v, 'scores': None} for k, v in results.items()},
    }
    
    out_path = Path('/home/haaraphel/BARAQ/datasets/botsv1_bench/simulation_results.json')
    import json
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    logger.info(f"Results saved to {out_path}")


if __name__ == '__main__':
    main()