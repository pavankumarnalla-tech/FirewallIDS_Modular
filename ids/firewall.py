"""Safe wrapper around the PowerShell firewall module. Dry-run is the default."""
from __future__ import annotations
import ipaddress
import subprocess
from pathlib import Path


def validate_private_lan_ip(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_multicast:
        raise ValueError("For this student demo, only a private IPv4 LAN address is allowed.")
    return str(ip)


def apply_block_rule(remote_ip: str, powershell_script: str = "powershell/FirewallManager.ps1",
                     confirm: bool = False) -> dict:
    """Add an inbound block rule only after explicit caller confirmation."""
    if not confirm:
        return {"status": "dry_run", "remote_ip": remote_ip,
                "message": "No firewall change made. Pass explicit confirmation to apply."}
    safe_ip = validate_private_lan_ip(remote_ip)
    script_path = Path(powershell_script).resolve()
    if not script_path.exists():
        raise FileNotFoundError(f"PowerShell module not found: {script_path}")
    command = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned",
        "-File", str(script_path), "-Action", "Add", "-RemoteIP", safe_ip
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    return {
        "status": "success" if result.returncode == 0 else "failed",
        "remote_ip": safe_ip,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }
