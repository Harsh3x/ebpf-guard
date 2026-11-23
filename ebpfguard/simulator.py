"""Synthetic container telemetry, used when eBPF/Docker/root are unavailable.

Normal: an nginx container (master -> worker, reads files, accepts requests,
talks to an internal database). Attacks mirror the "Industrial Use Case" slide.
"""
import random
from typing import Iterator, List, Optional

from . import events as E

DB = "10.0.0.5:5432"


def _normal(rng, t0, dur, c) -> List[E.Event]:
    out = []
    for _ in range(max(1, int(rng.gauss(2, 0.6)))):                    # worker processes
        out.append(E.Event(t0 + rng.uniform(0, dur), c, E.EXEC, comm="nginx"))
    for _ in range(int(rng.gauss(140, 12))):
        out.append(E.Event(t0 + rng.uniform(0, dur), c, E.OPEN, comm="nginx",
                           detail=f"/usr/share/nginx/html/{rng.randint(1, 40)}.html"))
    for _ in range(int(rng.gauss(4, 1))):
        out.append(E.Event(t0 + rng.uniform(0, dur), c, E.CONNECT, comm="nginx", detail=DB))
    out.append(E.Event(t0, c, E.SYSCALLS, n=int(rng.gauss(1250, 60))))
    out.append(E.Event(t0, c, E.WRITES, n=int(rng.gauss(300, 25))))
    return out


def _attack(kind, rng, t0, dur, c) -> List[E.Event]:
    ev = _normal(rng, t0, dur, c)
    r = lambda: t0 + rng.uniform(0, dur)
    if kind == "reverse_shell":        # nginx -> bash -> nc -> external connection
        ev += [E.Event(r(), c, E.EXEC, comm="bash"), E.Event(r(), c, E.EXEC, comm="nc"),
               E.Event(r(), c, E.CONNECT, comm="nc", detail="203.0.113.7:4444")]
    elif kind == "credential_theft":   # unauthorized file access
        ev += [E.Event(r(), c, E.OPEN, comm="cat", detail=p) for p in
               ["/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa", "/proc/1/environ"] * 3]
        ev.append(E.Event(r(), c, E.EXEC, comm="sh"))
    elif kind == "cryptominer":        # suspicious process + heavy syscalls + external pool
        ev += [E.Event(r(), c, E.EXEC, comm="xmrig"), E.Event(r(), c, E.EXEC, comm="wget"),
               E.Event(r(), c, E.CONNECT, comm="xmrig", detail="198.51.100.9:3333"),
               E.Event(t0, c, E.SYSCALLS, n=9000)]
    elif kind == "exfiltration":       # many external destinations
        ev += [E.Event(r(), c, E.CONNECT, comm="curl", detail=f"198.51.100.{i}:443") for i in range(25)]
        ev.append(E.Event(r(), c, E.EXEC, comm="curl"))
    return ev


ATTACKS = ["reverse_shell", "credential_theft", "cryptominer", "exfiltration"]


def stream(windows: int, window: float = 5.0, container: str = "web-1", seed: int = 1,
           attack_every: Optional[int] = None, attack: Optional[str] = None) -> Iterator[E.Event]:
    """Yield `windows` windows of events; every `attack_every`-th window is malicious."""
    rng = random.Random(seed)
    for i in range(windows):
        t0 = i * window
        if attack_every and i % attack_every == attack_every - 1:
            yield from _attack(attack or rng.choice(ATTACKS), rng, t0, window, container)
        else:
            yield from _normal(rng, t0, window, container)
