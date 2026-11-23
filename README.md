# ebpfguard — ML-based runtime container security using eBPF

Detects abnormal Docker container behaviour at runtime (no CVE signature needed):

```
Docker container → eBPF collection → feature extraction → autoencoder → anomaly score → alert
```

| Module | Role |
|---|---|
| `ebpfguard/collector_ebpf.py` | BCC tracepoints: execve, openat, connect + per-cgroup syscall/write counters; maps cgroup → Docker container |
| `ebpfguard/simulator.py` | Synthetic nginx telemetry + attacks (reverse shell, credential theft, cryptominer, exfiltration) |
| `ebpfguard/features.py` | 5 s windows → 12 features (process / file / network / system groups) |
| `ebpfguard/autoencoder.py` | PyTorch autoencoder trained on normal windows only; reconstruction error = anomaly score |
| `ebpfguard/detector.py` | Streaming per-container scoring, alerts with top contributing features |
| `docker/`, `docker-compose.yml` | Ready-made lab: nginx victim + traffic + privileged guard sensor |

## 1. Docker lab (real eBPF)
Requirements: Linux host (x86_64, kernel ≥ 5.8, cgroup v2, kernel headers installed), Docker + compose.
```bash
docker compose up -d --build victim traffic
docker compose up --build guard          # learns baseline ~1 min, then prints a line per window
# in another terminal, once it says ">> monitoring":
./scripts/attack.sh shell                # also: creds, scan
```
Expect `[ALERT] ... victim  score=... top: shell_execs, outbound_conns, ...`. Reset the baseline with
`docker compose down -v`. Tune with `TRAIN_WINDOWS` / `WINDOW` env vars on the guard service.

Without compose: `sudo python3 -m ebpfguard train --source ebpf --container victim --windows 60`
then `sudo python3 -m ebpfguard detect --source ebpf --container victim -v` (needs `python3-bpfcc`).

## 2. Simulator (no root/Docker needed)
```bash
pip install numpy pytest torch   # CPU torch: --index-url https://download.pytorch.org/whl/cpu
python -m ebpfguard demo
python -m pytest tests
```

## Status / caveats
- Simulator path and ML pipeline: tested (4 tests pass).
- Docker/eBPF path: written but **not run** in the dev environment (no Docker, no root). Expect to
  possibly debug BPF compile issues on your kernel the first time (the write() syscall number is x86_64 only).
- Baseline quality matters: train only on normal traffic; window-level model, one baseline per container.

## GUI (Portainer)
`docker compose up -d portainer`, then open http://localhost:9000, create the admin user, and pick
the *local* environment. You get container list, live logs (`guard`), stats and an exec console.
Docker Desktop's own window can't show this stack: it only sees its own VM-based engine, whose
kernel has no headers for the bcc-based sensor.
