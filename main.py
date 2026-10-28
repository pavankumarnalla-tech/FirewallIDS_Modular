"""Firewall IDS demo coordinator. Default operation only monitors/logs; it does not block."""
import argparse
import json
from pathlib import Path
from ids.monitor import monitor
from ids.detector import DetectionEngine
from ids.audit import AuditLogger
from ids.firewall import apply_block_rule


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run(args):
    config = load_config(args.config)
    audit = AuditLogger(config.get("log_file", "logs/ids_events.jsonl"))
    detector = DetectionEngine(
        threshold=config.get("new_connections_threshold", 8),
        window_seconds=config.get("window_seconds", 60),
        ignore_private_ips=config.get("ignore_private_ips_for_detection", False),
    )
    print("Firewall IDS started — monitoring only; no automatic blocking.")
    print("Press Ctrl+C to stop. Detection is heuristic and covers ESTABLISHED TCP connections only.")
    try:
        for event_obj in monitor(config.get("poll_interval_seconds", 2)):
            event = event_obj.to_dict()
            audit.write({"record_type": "connection", "event": event})
            print(f"[CONNECTION] {event['local_ip']}:{event['local_port']} -> "
                  f"{event['remote_ip']}:{event['remote_port']}")
            alert = detector.analyze(event)
            if alert:
                audit.write({"record_type": "alert", **alert})
                print(f"[ALERT/{alert['severity']}] {alert['reason']}")
                # No auto-blocking. The operator must use a separate explicit command.
    except KeyboardInterrupt:
        print("\nStopped.")
    print("Audit summary:", audit.report())


def main():
    parser = argparse.ArgumentParser(description="Modular Firewall Intrusion Detection demo")
    parser.add_argument("--config", default="config.json")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("monitor", help="Monitor established TCP connections and log heuristics")
    report = sub.add_parser("report", help="Show counts from the audit log")
    report.add_argument("--log", default=None)
    block = sub.add_parser("block-test-ip", help="Explicitly block a private LAN IP (admin required)")
    block.add_argument("--ip", required=True, help="Private IPv4 address of your own test device")
    block.add_argument("--confirm", action="store_true", help="Actually create the inbound block rule")
    cleanup = sub.add_parser("cleanup", help="Remove rules created by this project (admin required)")
    cleanup.add_argument("--confirm", action="store_true", help="Actually remove project rules")
    args = parser.parse_args()

    if args.command == "monitor":
        run(args)
    elif args.command == "report":
        logger = AuditLogger(args.log or load_config(args.config).get("log_file", "logs/ids_events.jsonl"))
        print(json.dumps(logger.report(), indent=2))
    elif args.command == "block-test-ip":
        result = apply_block_rule(args.ip, confirm=args.confirm)
        print(json.dumps(result, indent=2))
    elif args.command == "cleanup":
        import subprocess
        script = str(Path("powershell/FirewallManager.ps1").resolve())
        command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned",
                   "-File", script, "-Action", "Remove"]
        if not args.confirm:
            print("DRY RUN: no firewall rules removed. Re-run with --confirm from elevated PowerShell.")
        else:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            print(result.stdout)
            if result.stderr:
                print(result.stderr)
            raise SystemExit(result.returncode)

if __name__ == "__main__":
    main()
