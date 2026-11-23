"""Turn raw events into fixed-width time-window feature vectors.

Features follow the project's "Runtime Monitoring Using eBPF" design:
process, file, network and system groups.
"""
from collections import defaultdict
from typing import Dict, Iterable, List

import numpy as np

from . import events as E

SHELLS = {"sh", "bash", "dash", "zsh", "ash", "nc", "ncat", "netcat",
          "curl", "wget", "python", "python3", "perl", "socat"}
SENSITIVE_PREFIXES = ("/etc/shadow", "/etc/passwd", "/root/", "/proc/", "/var/run/docker.sock")

FEATURE_NAMES = [
    "procs_created", "unique_procs", "shell_execs",
    "file_opens", "file_writes", "unique_files", "sensitive_opens",
    "connections", "outbound_conns", "unique_dests",
    "syscalls", "event_rate",
]
N_FEATURES = len(FEATURE_NAMES)


def _is_private(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.")) or ip == "::1"


def window_features(evts: Iterable[E.Event], window: float) -> np.ndarray:
    procs: List[str] = []
    shells = 0
    opens = writes = sensitive = syscalls = 0
    files = set()
    conns = outbound = 0
    dests = set()
    total = 0
    for e in evts:
        total += 1
        if e.kind == E.EXEC:
            procs.append(e.comm)
            shells += e.comm in SHELLS
        elif e.kind == E.OPEN:
            opens += 1
            files.add(e.detail)
            sensitive += e.detail.startswith(SENSITIVE_PREFIXES)
        elif e.kind == E.WRITES:
            writes += e.n
        elif e.kind == E.SYSCALLS:
            syscalls += e.n
        elif e.kind == E.CONNECT:
            conns += 1
            ip = e.detail.rsplit(":", 1)[0]
            dests.add(e.detail)
            outbound += not _is_private(ip)
    return np.array([
        len(procs), len(set(procs)), shells,
        opens, writes, len(files), sensitive,
        conns, outbound, len(dests),
        syscalls, total / window,
    ], dtype=float)


def windowize(evts: Iterable[E.Event], window: float = 5.0) -> Dict[str, List[np.ndarray]]:
    """Bucket a (finite) event stream into per-container window vectors."""
    buckets = defaultdict(lambda: defaultdict(list))
    for e in evts:
        buckets[e.container][int(e.ts // window)].append(e)
    out = {}
    for c, b in buckets.items():
        out[c] = [window_features(b[i], window) for i in sorted(b)]
    return out
