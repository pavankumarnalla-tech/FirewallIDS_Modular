"""Member 2: Transparent heuristic detection; never labels an IP as certainly malicious."""
# Analyzes observed network connection events for suspicious activity.
# Tracks unique connections from each remote IP within a configurable time window.
# Raises transparent heuristic alerts when the configured connection threshold is reached.
# It reports indicators of a possible burst without declaring an IP definitively malicious.
from __future__ import annotations
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import ipaddress


class DetectionEngine:
    def __init__(self, threshold: int = 8, window_seconds: int = 60,
                 ignore_private_ips: bool = False):
        self.threshold = max(2, int(threshold))
        self.window = timedelta(seconds=max(5, int(window_seconds)))
        self.ignore_private_ips = ignore_private_ips
        self.events_by_ip = defaultdict(deque)

    def analyze(self, event: dict) -> dict | None:
        """Count distinct newly observed connections per remote IP in a rolling window."""
        ip = event["remote_ip"]
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if self.ignore_private_ips and parsed.is_private:
            return None

        try:
            stamp = datetime.fromisoformat(event["timestamp"])
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
        except (KeyError, ValueError, TypeError):
            stamp = datetime.now(timezone.utc)

        history = self.events_by_ip[ip]
        key = event.get("key", f'{ip}:{event.get("remote_port", 0)}')
        # Do not count the same connection twice.
        if any(existing_key == key for _, existing_key in history):
            return None
        history.append((stamp, key))
        cutoff = stamp - self.window
        while history and history[0][0] < cutoff:
            history.popleft()

        count = len(history)
        if count >= self.threshold:
            return {
                "type": "connection_burst_heuristic",
                "severity": "HIGH" if count >= self.threshold * 2 else "MEDIUM",
                "remote_ip": ip,
                "count": count,
                "window_seconds": int(self.window.total_seconds()),
                "reason": (
                    f"{count} newly observed established TCP connections from {ip} "
                    f"within {int(self.window.total_seconds())} seconds; threshold={self.threshold}. "
                    "This is a heuristic, not proof of an attack."
                ),
                "source_event": event,
            }
        return None
