"""Member 3: Append-only JSON Lines audit logging and summary reporting."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone


class AuditLogger:
    def __init__(self, path: str = "logs/ids_events.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: dict) -> None:
        row = {
            "logged_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **record,
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    def report(self) -> dict:
        counts = {"events": 0, "alerts": 0, "firewall_actions": 0}
        if not self.path.exists():
            return counts
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                counts["events"] += 1
                if row.get("record_type") == "alert":
                    counts["alerts"] += 1
                if row.get("record_type") == "firewall_action":
                    counts["firewall_actions"] += 1
        return counts
