"""Common event model shared by the eBPF collector and the simulator."""
from dataclasses import dataclass

# Event kinds
EXEC = "exec"                # a process was executed (execve)
OPEN = "open"                # a file was opened (openat)
CONNECT = "connect"          # outbound connection (connect)
SYSCALLS = "syscalls"        # aggregated syscall counter delta (n = count)
WRITES = "writes"            # aggregated write() counter delta (n = count)


@dataclass
class Event:
    ts: float                # seconds (monotonic or simulated)
    container: str           # container name / id
    kind: str
    pid: int = 0
    comm: str = ""           # process name
    detail: str = ""         # file path, or "ip:port" for connect
    n: int = 1               # multiplicity for aggregated kinds
