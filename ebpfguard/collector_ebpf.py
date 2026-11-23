"""Real eBPF collector (BCC). Requires root, Linux >= 5.8, cgroup v2 and `bcc`.

Attaches tracepoints for execve / openat / connect and counts all syscalls and
write() calls per cgroup in kernel maps. cgroup ids are mapped to Docker
containers by matching the inode of /sys/fs/cgroup/**/docker-<id>.scope.
"""
import glob
import os
import subprocess
import time
from typing import Dict, Iterator

from . import events as E

BPF_SRC = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>

enum { K_EXEC = 1, K_OPEN = 2, K_CONNECT = 3 };
struct ev_t {
    u64 cg; u32 pid; u32 kind; u32 ip; u16 port; char comm[16]; char path[128];
};
BPF_PERF_OUTPUT(events);
BPF_HASH(syscalls, u64, u64);   // cgroup id -> total syscalls
BPF_HASH(writes, u64, u64);     // cgroup id -> write() calls
BPF_HASH(watch, u64, u8);       // cgroup ids to monitor (filled from user space)
static __always_inline int watched(u64 cg) { return watch.lookup(&cg) != 0; }

RAW_TRACEPOINT_PROBE(sys_enter) {
    u64 cg = bpf_get_current_cgroup_id(), zero = 0, *v;
    if (!watched(cg)) return 0;
    v = syscalls.lookup_or_try_init(&cg, &zero);
    if (v) __sync_fetch_and_add(v, 1);
    if (ctx->args[1] == 1) {    // __NR_write (x86_64)
        v = writes.lookup_or_try_init(&cg, &zero);
        if (v) __sync_fetch_and_add(v, 1);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct ev_t e = {.kind = K_EXEC};
    e.cg = bpf_get_current_cgroup_id(); if (!watched(e.cg)) return 0;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(&e.path, sizeof(e.path), args->filename);
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct ev_t e = {.kind = K_OPEN};
    e.cg = bpf_get_current_cgroup_id(); if (!watched(e.cg)) return 0;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(&e.path, sizeof(e.path), args->filename);
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), args->uservaddr);
    if (sa.sin_family != AF_INET) return 0;
    struct ev_t e = {.kind = K_CONNECT};
    e.cg = bpf_get_current_cgroup_id(); if (!watched(e.cg)) return 0;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ip = sa.sin_addr.s_addr; e.port = ntohs(sa.sin_port);
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""


def docker_cgroups() -> Dict[int, str]:
    """cgroup id (inode) -> container name (or 12-char id if the docker CLI is unavailable)."""
    by_id = {}
    try:
        for line in subprocess.check_output(["docker", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"],
                                            text=True, stderr=subprocess.DEVNULL).splitlines():
            cid, name = line.split(" ", 1)
            by_id[cid] = name
    except Exception:
        pass
    out = {}
    pats = ["/sys/fs/cgroup/**/docker-*.scope", "/sys/fs/cgroup/docker/*", "/sys/fs/cgroup/**/docker/*"]
    for pat in pats:
        for path in glob.glob(pat, recursive=True):
            cid = os.path.basename(path).replace("docker-", "").replace(".scope", "")
            if len(cid) == 64 and os.path.isdir(path):
                out[os.stat(path).st_ino] = by_id.get(cid, cid[:12])
    return out


def collect(window: float = 5.0, name_filter: str = None, only_containers: bool = True) -> Iterator[E.Event]:
    """Yield Events forever. Counter maps are flushed as SYSCALLS/WRITES events."""
    from bcc import BPF  # imported lazily: optional dependency
    import ctypes as ct
    import socket
    import struct

    b = BPF(text=BPF_SRC)
    pending, cgs, last_scan = [], docker_cgroups(), 0.0
    last = {"syscalls": {}, "writes": {}}

    def refresh():
        """Re-scan Docker cgroups and tell the kernel which ones to watch."""
        cgs.update(docker_cgroups())
        for cg, name in cgs.items():
            if not name_filter or name_filter in name:
                b["watch"][ct.c_uint64(cg)] = ct.c_ubyte(1)

    def name_of(cg: int):
        return cgs.get(cg)

    def on_event(cpu, data, size):
        e = b["events"].event(data)
        c = name_of(e.cg)
        if c is None:
            return
        comm = os.path.basename(e.path.decode(errors="replace")) if e.kind == 1 else e.comm.decode(errors="replace")
        detail = {1: "", 2: e.path.decode(errors="replace"),
                  3: f"{socket.inet_ntoa(struct.pack('I', e.ip))}:{e.port}"}[e.kind]
        pending.append(E.Event(time.time(), c, {1: E.EXEC, 2: E.OPEN, 3: E.CONNECT}[e.kind],
                               e.pid, comm, detail))

    b["events"].open_perf_buffer(on_event, page_cnt=64)
    refresh()
    while True:
        deadline = time.time() + 0.5
        while time.time() < deadline:
            b.perf_buffer_poll(timeout=100)
        now = time.time()
        if now - last_scan > 2:
            refresh(); last_scan = now
        for mapname, kind in (("syscalls", E.SYSCALLS), ("writes", E.WRITES)):
            for k, v in b[mapname].items():
                prev = last[mapname].get(k.value, 0)
                last[mapname][k.value] = v.value
                c = name_of(k.value)
                if c is not None and v.value > prev:
                    pending.append(E.Event(now, c, kind, n=v.value - prev))
        out, pending[:] = list(pending), []
        yield from out
