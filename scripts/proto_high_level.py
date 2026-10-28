#!/usr/bin/env python3
"""High-level network ML feature extraction — causal, streaming prototype.

This is the single source of truth for the high-level feature schema.
Used by both offline benchmark and live scoring path.
"""
from __future__ import annotations
import math, datetime
from collections import defaultdict, deque
from dataclasses import dataclass
import numpy as np, pandas as pd

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

FEATURE_VERSION = 1  # bump when FEATURES changes

def entropy(vals):
    if not vals: return 0.0
    c=defaultdict(int)
    for v in vals: c[v]+=1
    n=len(vals); h=-sum((x/n)*math.log2(x/n) for x in c.values())
    return h/math.log2(max(2,len(c)))

def path_entropy(s):
    return entropy(list(s.lower())) if s else 0.0

def domain_shape(d):
    d=(d or '').strip().lower()
    if not d: return 0,0,0,0,0
    labels=d.split('.')
    digits=sum(ch.isdigit() for ch in d)/max(1,len(d))
    return 1, entropy(list(d)), digits, len(labels), len(d)

def is_private(ip):
    return ip.startswith(('10.','192.168.','172.16.','172.17.','172.18.','172.19.','172.2','172.3','127.'))

@dataclass
class Flow:
    ts: float
    src: str
    dst: str
    port: int
    process: str = ''
    domain: str = ''
    service: str = ''
    state: str = ''
    bsent: int = 0
    brecv: int = 0
    duration: float = 0.0

class Profiler:
    """Causal streaming profiler — state updated AFTER feature computation."""
    def __init__(self):
        self.n=0
        self.host_count=defaultdict(int); self.host_dsts=defaultdict(set); self.host_ports=defaultdict(set); self.host_procs=defaultdict(set)
        self.host_ext_flows=defaultdict(int); self.host_ext_dsts=defaultdict(set); self.host_ext_ports=defaultdict(set)
        self.proc_count=defaultdict(int); self.proc_hosts=defaultdict(set); self.proc_ext_count=defaultdict(int); self.proc_ext_hosts=defaultdict(set)
        self.dst_count=defaultdict(int); self.dst_hosts=defaultdict(set); self.dst_ports=defaultdict(set); self.dst_procs=defaultdict(set)
        self.port_count=defaultdict(int); self.port_hosts=defaultdict(set)
        self.domain_count=defaultdict(int); self.domain_hosts=defaultdict(set)
        self.pair_ts=defaultdict(lambda: deque(maxlen=32)); self.pair_count=defaultdict(int); self.pair_ext_count=defaultdict(int)
        self.host_ts=defaultdict(lambda: deque(maxlen=256))
        # process/host-process context
        self.proc_dsts=defaultdict(set); self.proc_ports=defaultdict(set); self.proc_pairs=defaultdict(set)
        self.proc_ext_dsts=defaultdict(set); self.proc_ext_ports=defaultdict(set)
        self.proc_dst_hosts=defaultdict(set); self.proc_dst_count=defaultdict(int); self.proc_pair_count=defaultdict(int)
        self.host_proc_dsts=defaultdict(set); self.host_proc_pairs=defaultdict(set); self.host_proc_ext_dsts=defaultdict(set); self.host_proc_ext_ports=defaultdict(set)
        self.host_proc_count=defaultdict(int); self.host_proc_ext_count=defaultdict(int)

    def features(self, f: Flow) -> list[float]:
        dt=datetime.datetime.fromtimestamp(f.ts, datetime.UTC)
        hour=dt.hour
        hour_sin=math.sin(2*math.pi*hour/24); hour_cos=math.cos(2*math.pi*hour/24)
        is_night=1.0 if hour in (22,23,0,1,2,3,4,5) else 0.0
        is_weekend=1.0 if dt.weekday()>=5 else 0.0
        dst=f.dst or ''; port=int(f.port or 0); src=f.src or ''; proc=f.process or ''
        priv=is_private(dst); ext=1.0-priv
        n=max(1,self.n)
        dst_novel=1.0 if dst and self.dst_count.get(dst,0)==0 else 0.0
        port_rarity=1.0-(self.port_count.get(port,0)/n) if port else 0.0
        pc=self.proc_count.get(proc,0); pec=self.proc_ext_count.get(proc,0)
        process_rarity=1.0-(pc/n) if proc else 1.0
        proc_low=proc.lower()
        user_writable=1.0 if any(t in proc_low for t in ('\\appdata\\','/tmp/','\\temp\\','\\downloads\\','\\public\\','/home/','/var/tmp/')) else 0.0
        system_path=1.0 if any(t in proc_low for t in ('\\windows\\system32\\','\\windows\\syswow64\\','/usr/bin/','/usr/sbin/','/bin/')) else 0.0
        pkey=(src,dst,port); pts=self.pair_ts.get(pkey); pair_ct=self.pair_count.get(pkey,0)
        if pts and len(pts)>=2:
            arr=np.asarray(pts,dtype=float); intervals=np.diff(arr); mean=float(intervals.mean()) if len(intervals) else 0.0
            cv=float(intervals.std()/mean) if mean>1e-9 else 0.0
            ient=entropy([round(float(x),1) for x in intervals]); beac=1.0/(1.0+cv) if len(intervals)>=2 else 0.0
            time_since=float(f.ts-arr[-1]) if f.ts>=arr[-1] else 0.0
        else:
            cv=0.0; ient=0.0; beac=0.0; time_since=0.0
        pair_novel=1.0 if pair_ct==0 else 0.0
        hts=self.host_ts.get(src); rate1=rate10=0.0
        if hts:
            arr=np.asarray(hts,dtype=float); rate1=float(((f.ts-arr)<=60).sum()); rate10=float(((f.ts-arr)<=600).sum())/10.0
        dom=f.domain or ''; dp,de,dd,dl,dlen=domain_shape(dom); dnovel=1.0 if dom and self.domain_count.get(dom,0)==0 else 0.0
        bs=max(0,f.bsent or 0); br=max(0,f.brecv or 0); dur=max(0,f.duration or 0)
        sent_log=math.log1p(bs); recv_log=math.log1p(br); asym=(bs+1)/(br+1); bps=(bs+br)/max(dur,1e-3) if (bs+br)>0 else 0.0
        service=(f.service or '').lower(); state=(f.state or '').upper(); svc=lambda x: 1.0 if x in service else 0.0
        # external interactions
        dst_hosts=len(self.dst_hosts.get(dst,())); dst_procs=len(self.dst_procs.get(dst,())); dst_ports=len(self.dst_ports.get(dst,()))
        src_ext=len(self.host_ext_dsts.get(src,())); src_all=len(self.host_dsts.get(src,()))
        proc_ext_hosts=len(self.proc_ext_hosts.get(proc,())); proc_hosts=len(self.proc_hosts.get(proc,()))
        ext_pair_ct=self.pair_ext_count.get(pkey,0)
        e_dst_novel=ext*dst_novel
        e_dst_count=ext*math.log1p(self.dst_count.get(dst,0))
        e_dst_hosts=ext*math.log1p(dst_hosts)
        e_dst_procs=ext*math.log1p(dst_procs)
        e_dst_ports=ext*math.log1p(dst_ports)
        e_proc_hosts=ext*math.log1p(proc_ext_hosts)
        e_proc_ratio=ext*(pec/(pc+1))
        e_port_hosts=ext*math.log1p(len(self.port_hosts.get(port,())))
        e_src_fanout=ext*math.log1p(src_ext)
        e_src_new=ext*(1.0-(self.host_ext_flows.get(src,0)/max(1,self.host_count.get(src,0))))
        e_host_ratio=self.host_ext_flows.get(src,0)/max(1,self.host_count.get(src,0))
        e_src_ports=ext*math.log1p(len(self.host_ext_ports.get(src,())))
        e_dst_src_ratio=ext*((dst_hosts+1)/(src_all+1))
        e_dst_per_host=ext*((dst_hosts+1)/(len(self.host_dsts.get(src,()))+1))
        e_pair_novel=ext*pair_novel
        e_pair_count=ext*math.log1p(ext_pair_ct)
        e_fanin_x_count=e_dst_hosts*e_dst_count
        e_fanout_x_ports=e_src_fanout*e_src_ports
        e_proc_x_ratio=e_proc_hosts*e_proc_ratio
        # process/host-process context
        hpk=(src,proc)
        proc_dst_n=1 if (proc,dst) not in self.proc_dst_count else 0
        proc_port_n=1 if port not in self.proc_ports.get(proc,()) else 0
        proc_pair_n=1 if (proc,dst,port) not in self.proc_pair_count else 0
        host_proc_dst_n=1 if dst not in self.host_proc_dsts.get(hpk,()) else 0
        host_proc_pair_n=1 if (dst,port) not in self.host_proc_pairs.get(hpk,()) else 0
        proc_dst_count=self.proc_dst_count.get((proc,dst),0)
        proc_dst_hosts=len(self.proc_dst_hosts.get((proc,dst),()))
        proc_ext_dsts=len(self.proc_ext_dsts.get(proc,()))
        proc_ext_ports=len(self.proc_ext_ports.get(proc,()))
        proc_ext_ct=self.proc_ext_count.get(proc,0)
        host_proc_ct=self.host_proc_count.get(hpk,0)
        host_proc_ext_ct=self.host_proc_ext_count.get(hpk,0)
        hproc_ratio=host_proc_ext_ct/max(1,host_proc_ct)
        hproc_ext_dsts=len(self.host_proc_ext_dsts.get(hpk,()))
        hproc_new_ratio=1.0-(host_proc_ext_ct/max(1,host_proc_ct)) if host_proc_ct else 1.0
        return [
            hour_sin,hour_cos,is_night,is_weekend,
            port/65535.0,port_rarity,math.log1p(len(self.port_hosts.get(port,()))),1.0 if 0<port<1024 else 0.0,1.0 if port>=49152 else 0.0,
            priv,1.0 if dst in ('127.0.0.1','::1') else 0.0,1.0 if dst.startswith(('224.','239.','255.')) else 0.0,dst_novel,math.log1p(self.dst_count.get(dst,0)),math.log1p(dst_hosts),
            math.log1p(self.host_count.get(src,0)),math.log1p(len(self.host_dsts.get(src,()))),math.log1p(len(self.host_ports.get(src,()))),math.log1p(len(self.host_procs.get(src,()))),
            1.0 if pc>0 else 0.0,math.log1p(pc),process_rarity,math.log1p(proc_hosts),user_writable,system_path,path_entropy(proc),math.log1p(len(proc)),
            pair_novel,math.log1p(pair_ct),math.log1p(1+time_since),cv,ient,beac,0.0,
            rate1,rate10,0.0,0.0,(len(self.host_dsts.get(src,()))+1)/(len(self.dst_hosts.get(dst,()))+1),
            dp,dnovel,de,dd,dl,math.log1p(dlen),
            sent_log,recv_log,asym,math.log1p(bps),math.log1p(dur),
            svc('dns'),svc('http'),svc('ssl'),svc('smb'),svc('dce_rpc'),1.0 if state.startswith('S0') else 0.0,1.0 if state in ('REJ','RST') else 0.0,1.0 if state.startswith('RSTO') else 0.0,
            e_dst_novel,e_dst_count,e_dst_hosts,e_dst_procs,e_dst_ports,
            e_proc_hosts,e_proc_ratio,e_port_hosts,
            e_src_fanout,e_src_new,e_host_ratio,e_src_ports,
            e_dst_src_ratio,e_dst_per_host,e_pair_novel,e_pair_count,
            e_fanin_x_count,e_fanout_x_ports,e_proc_x_ratio,
            ext*proc_dst_n,ext*proc_port_n,ext*proc_pair_n,
            ext*host_proc_dst_n,ext*host_proc_pair_n,
            ext*math.log1p(proc_dst_count),ext*math.log1p(proc_dst_hosts),ext*math.log1p(proc_ext_dsts),ext*math.log1p(proc_ext_ports),
            ext*math.log1p(proc_ext_ct),ext*e_proc_ratio*math.log1p(proc_ext_ct),ext*e_proc_ratio*math.log1p(proc_hosts),
            ext*math.log1p(host_proc_ext_ct)*hproc_ratio,ext*math.log1p(hproc_ext_dsts),ext*hproc_new_ratio,
        ]

    def update(self,f: Flow):
        self.n+=1
        src=f.src or ''; dst=f.dst or ''; port=int(f.port or 0); proc=f.process or ''; dom=f.domain or ''; ext=not is_private(dst)
        self.host_count[src]+=1; self.host_dsts[src].add(dst); self.host_ports[src].add(port); self.host_procs[src].add(proc)
        if ext:
            self.host_ext_flows[src]+=1; self.host_ext_dsts[src].add(dst); self.host_ext_ports[src].add(port)
        self.proc_count[proc]+=1; self.proc_hosts[proc].add(src)
        if ext:
            self.proc_ext_count[proc]+=1; self.proc_ext_hosts[proc].add(src)
        if dst:
            self.dst_count[dst]+=1; self.dst_hosts[dst].add(src); self.dst_ports[dst].add(port); self.dst_procs[dst].add(proc)
        self.port_count[port]+=1; self.port_hosts[port].add(src)
        if dom:
            self.domain_count[dom]+=1; self.domain_hosts[dom].add(src)
        pkey=(src,dst,port); self.pair_count[pkey]+=1; self.pair_ext_count[pkey]+= (1 if ext else 0); self.pair_ts[pkey].append(f.ts)
        self.proc_dsts[proc].add(dst); self.proc_ports[proc].add(port); self.proc_pairs[proc].add((dst,port))
        if ext:
            self.proc_ext_dsts[proc].add(dst); self.proc_ext_ports[proc].add(port)
            self.host_proc_ext_dsts[(src,proc)].add(dst); self.host_proc_ext_ports[(src,proc)].add(port)
        self.proc_dst_hosts[(proc,dst)].add(src); self.proc_dst_count[(proc,dst)]+=1; self.proc_pair_count[(proc,dst,port)]+=1
        self.host_proc_dsts[(src,proc)].add(dst); self.host_proc_pairs[(src,proc)].add((dst,port))
        self.host_proc_count[(src,proc)]+=1
        if ext: self.host_proc_ext_count[(src,proc)]+=1
        self.host_ts[src].append(f.ts)

def flow_from_meta(r) -> Flow:
    return Flow(ts=pd.Timestamp(r.ts).timestamp(),src=str(r.host or ''),dst=str(r.dst_ip or ''),port=int(r.dst_port or 0),process=str(r.image or ''),domain=str(r.dst_host or ''))

def flow_from_conn(r) -> Flow:
    """For live NetworkConnection rows (columns: observed_at, process, remote_ip, remote_port, state, ...)"""
    return Flow(ts=pd.Timestamp(r.observed_at).timestamp(),src='',dst=str(r.remote_ip or ''),port=int(r.remote_port or 0),process=str(r.process or ''),domain='',state=str(r.state or ''))

def build(df):
    df=df.sort_values('ts').reset_index(drop=True); p=Profiler(); X=[]
    for r in df.itertuples(index=False):
        f=flow_from_meta(r); X.append(p.features(f)); p.update(f)
    return np.asarray(X,dtype=np.float32)

def build_local(df):
    """Build from local_flows.csv (columns: observed_at, process, local_ip, local_port, remote_ip, remote_port, state)"""
    df=df.sort_values('observed_at').reset_index(drop=True); p=Profiler(); X=[]
    for r in df.itertuples(index=False):
        f=Flow(ts=pd.Timestamp(r.observed_at).timestamp(),src=str(r.local_ip or ''),dst=str(r.remote_ip or ''),port=int(r.remote_port or 0),process=str(r.process or ''),state=str(r.state or ''))
        X.append(p.features(f)); p.update(f)
    return np.asarray(X,dtype=np.float32)

if __name__=='__main__':
    import sys
    if len(sys.argv)>1 and sys.argv[1]=='local':
        df=pd.read_csv('/home/haaraphel/BARAQ/datasets/botsv1_bench/local_flows.csv')
        X=build_local(df)
        np.save('/home/haaraphel/BARAQ/datasets/botsv1_bench/local_X_hl.npy',X)
        print('local X',X.shape,'features',len(FEATURES))
    else:
        m=pd.read_pickle('/home/haaraphel/BARAQ/datasets/botsv1_bench/meta.pkl')
        X=build(m)
        np.save('/home/haaraphel/BARAQ/datasets/botsv1_bench/X_hl.npy',X)
        print('X',X.shape,'nan',np.isnan(X).sum(),'features',len(FEATURES))