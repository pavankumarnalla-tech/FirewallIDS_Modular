# Modular Firewall Intrusion Detection System (Python + PowerShell)

## Project scope
This student prototype has three modules: (1) TCP connection collection, (2) transparent heuristic detection, and (3) audit logging/reporting plus an explicitly invoked Windows Firewall manager. It is **not a commercial IDS** and does not inspect packet payloads or reliably detect failed SYN scans. It observes **established TCP connections** visible to Windows, so results depend on permissions and polling frequency.

The detector flags a configurable burst of newly observed established connections from one remote IP within a time window. That is a heuristic: it can produce false positives and does not prove malicious intent.

## Team of 3
- **Member 1 — Monitoring/data collection:** `ids/monitor.py`, connection-event format, `config.json`.
- **Member 2 — Detection logic and tests:** `ids/detector.py`, `tests/test_detector.py`, threshold/window experiments.
- **Member 3 — Response/audit/reporting:** `ids/firewall.py`, `ids/audit.py`, `powershell/FirewallManager.ps1`, report/cleanup demonstration.
- Integration owner (rotate/agree as a team): `main.py`, end-to-end tests and README. Every member should understand the full flow.

## Requirements
- Windows 10/11, Python 3.10+, Windows PowerShell 5.1, administrator rights only for firewall management.
- Install dependencies: `py -m pip install -r requirements.txt`
- Run commands from this project folder.

## Demo 1: monitor safely (no firewall modifications)
```powershell
py main.py monitor
```
Stop with Ctrl+C. Connection and alert events are written to `logs/ids_events.jsonl`.

## Demo 2: test detection with synthetic events
```powershell
py -m unittest discover -s tests -v
```
These tests do not require network attacks or firewall changes. To show the detector in a presentation, explain that synthetic events test the rule logic separately from live monitoring.

## Demo 3: report
```powershell
py main.py report
```

## Demo 4: explicitly test firewall response on your own LAN
1. In Fing, identify the **phone's private Wi-Fi IP** and verify it is your own phone on your own network.
2. Confirm the laptop is on the same trusted private Wi-Fi. This rule blocks inbound connections from that phone to the laptop; it does not disconnect the phone from Wi-Fi or block the phone's outbound internet.
3. Open PowerShell as Administrator in this project folder.
4. First do a dry run (does not change the firewall):
```powershell
py main.py block-test-ip --ip 192.168.1.50
```
Replace the sample IP with your phone's actual private IPv4 address.
5. Only if you intentionally want to test the rule, run:
```powershell
py main.py block-test-ip --ip 192.168.1.50 --confirm
```
6. Verify in `wf.msc` > Inbound Rules for `StudentIDS_Demo_192-168-1-50`. Confirm Enabled, Action=Block, Direction=Inbound, Remote address=phone IP. A rule existing proves it was created, not that an app connection was blocked. To test traffic blocking, you need a known service listening on the laptop and a connection attempt from the phone; many phones/Fing scans won't do this by default.

## Cleanup
From elevated PowerShell:
```powershell
py main.py cleanup
py main.py cleanup --confirm
```
The first command is a dry run; the second removes only rules with the `StudentIDS_Demo_` prefix created by this project.

## Important safety/accuracy notes
- Do not automatically block every IP in a connection list. Legitimate websites/services appear there.
- Default monitoring does not change firewall rules.
- Firewall rules persist after the script exits; remove project-created rules with cleanup.
- Private IP validation is a guardrail for a classroom demo, not a complete security boundary.
- Firewall module uses the Windows **Private** profile only; verify your network is marked Private before testing.
- If PowerShell script execution is restricted by an organizational policy, follow your institution's IT rules rather than bypassing them.

## Suggested evaluation evidence
1. Unit-test output (threshold, below-threshold, duplicate event tests).
2. Screenshot of live connection events and generated JSONL log.
3. Alert record with reason/count/window.
4. Firewall rule properties after explicit test, then cleanup confirmation.
5. Explain limitations: no packet inspection, polling can miss short connections, established TCP is not failed login/port-scan telemetry, and threshold heuristics can false-positive.
