"""Member 1: Collect snapshots of established TCP connections on Windows."""
# Collects snapshots of currently established TCP connections on Windows.
# Filters out invalid, local-only, and non-established connections before creating events.
# Converts each valid connection into a structured event with endpoint and timestamp data.
# The monitor yields only newly observed connections to avoid duplicate processing.
from __future__ import annotations
import ipaddress
import socket
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Iterable
import psutil


@dataclass(frozen=True)
class ConnectionEvent:
    timestamp: str
    remote_ip: str
    remote_port: int
    local_ip: str
    local_port: int
    status: str
    key: str

    def to_dict(self) -> dict:
        return asdict(self)


def _valid_remote_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)
    except ValueError:
        return False


def collect_established_connections() -> list[ConnectionEvent]:
    """Return current ESTABLISHED TCP connections, not failed/SYN attempts."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    events: list[ConnectionEvent] = []
    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError) as exc:
        raise RuntimeError(
            "Cannot read TCP connections. Try running PowerShell/Terminal as Administrator."
        ) from exc

    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not conn.laddr:
            continue
        remote_ip, remote_port = conn.raddr.ip, conn.raddr.port
        local_ip, local_port = conn.laddr.ip, conn.laddr.port
        if not _valid_remote_ip(remote_ip):
            continue
        key = f"{local_ip}:{local_port}->{remote_ip}:{remote_port}"
        events.append(ConnectionEvent(
            timestamp=now, remote_ip=remote_ip, remote_port=remote_port,
            local_ip=local_ip, local_port=local_port, status=conn.status, key=key
        ))
    return events


def monitor(poll_interval: float = 2.0):
    """Yield newly observed established connections; snapshots are deduplicated."""
    seen_keys: set[str] = set()
    while True:
        for event in collect_established_connections():
            if event.key not in seen_keys:
                seen_keys.add(event.key)
                yield event
        # Prevent unbounded memory growth in long-running sessions.
        if len(seen_keys) > 10000:
            seen_keys.clear()
        time.sleep(max(0.5, poll_interval))
