# Mitchel Kitavi SOC Analyst Portfolio Summary

## Project: Windows Endpoint Detection Lab — Sysmon + Splunk SIEM with Adversary Simulation

**Status:** Operational · **Role:** Solo · **Duration:** Multi sessions

---

**Multi-bullet detail:**
- Deployed **Sysmon 15.20** with SwiftOnSecurity's community config to capture enriched process, network, file, and DNS telemetry on a Windows 10/11 endpoint.
- Stood up **Splunk Enterprise** with a dedicated `winlogs` index, configuring four Windows Event Log inputs (Security, System, Application, Sysmon Operational) via a combination of GUI and manual `inputs.conf` editing verified with `splunk btool`.
- Enabled native **Windows process-creation auditing** (Event ID 4688) with command-line logging via `auditpol` and registry modification.
- Installed **Atomic Red Team** and executed benign adversary simulations for MITRE ATT&CK T1059.001 (PowerShell encoded command execution) after reviewing each test with `-ShowDetails` to confirm safety.
- **Validated detection pipeline end-to-end** by generating telemetry for a base64-encoded PowerShell execution and confirming capture via SPL detection query — first detection fire achieved with full forensic context (hashes, ProcessGuid, parent command line, integrity level).
- **Performed authentic incident response** after a Mimikatz atomic test triggered unexpectedly: queried Sysmon network and process data to confirm the download cradle was blocked, documented the exercise, and cleaned up artifacts — a realistic IR workflow.
- Diagnosed and resolved SIEM issues including raw-XML Sysmon ingestion (Splunk Add-on for Sysmon not yet installed) and third-party AV interaction with Microsoft Defender in SxS Passive Mode.

---

## Skills Learned

### Technical
- **SIEM administration:** Splunk Enterprise installation, index/input configuration, `btool` verification, SPL query authoring
- **Endpoint logging:** Sysmon deployment and tuning, Windows audit policy (`auditpol`), Event Viewer forensics
- **Windows internals:** Process creation events (4688 vs Sysmon 1), parent-child process relationships, command-line forensics, Defender SxS Passive Mode behavior
- **Adversary simulation:** Atomic Red Team framework, manual TTP execution, MITRE ATT&CK mapping
- **PowerShell:** Administrative scripting, module management, configuration verification, base64 decoding for IOC analysis
- **Configuration management:** Layered `.conf` file precedence, manual edits vs GUI trade-offs
- **Incident response:** Scope assessment using SIEM queries, artifact hunting, containment validation, controlled cleanup

### Methodology
- **MITRE ATT&CK framework:** Technique mapping (T1059.001, T1566.001, T1105, T1036, T1110, T1027)
- **Detection engineering:** Write query → simulate TTP → verify fire → tune iterative loop
- **Threat hunting:** Raw-text and field-extracted SPL queries for pivoting on indicators
- **Blue-team tradecraft:** `-ShowDetails` discipline, safe test selection, forensic query patterns
- **Documentation:** Portfolio-grade write-ups with reproducible commands, references, and lessons learned

### Tools
`Sysmon` · `Splunk Enterprise` · `Atomic Red Team / Invoke-AtomicRedTeam` · `Windows Event Viewer` · `PowerShell` · `auditpol` · `SwiftOnSecurity Sysmon Config` · `MITRE ATT&CK` · `SPL` · `splunk btool`

---

## Key Artifacts

| Artifact | Purpose |
|---|---|
| `inputs.conf` | Splunk data input configuration for 4 Windows log sources |
| `sysmonconfig-export.xml` | SwiftOnSecurity Sysmon configuration |
| SPL detection queries (7+) | Detections mapped to MITRE ATT&CK techniques |
| Validated detection: T1059.001 | Confirmed firing on real PowerShell encoded command |
| IR exercise documentation | Forensic workflow applied to accidental Mimikatz test |
| Atomic Red Team test library | MITRE-aligned adversary simulation toolkit |
| GitHub README | Full reproducible project documentation |

---

## 🎯 Featured Milestone: First Detection Fire

**Date:** April 23, 2026  
**MITRE Technique:** T1059.001 (Command and Scripting Interpreter: PowerShell) / T1027 (Obfuscated Files or Information)  
**Attack Simulation:**
```powershell
powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAZgByAG8AbQAgAHQAaABlACAAYQB0AHQAYQBjAGsAZQByACIA
```
Base64 decodes to: `Write-Host "Hello from the attacker"` (benign — technique demonstration only)

**Detection Query:**
```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
  powershell.exe EncodedCommand
```

**Result:** 1 event — detection fired. Forensic context retrieved: Image, full CommandLine with encoded payload, ParentImage, User, SHA256/MD5/IMPHASH hashes, ProcessGuid.

This closed the loop on the full SOC detection workflow — from policy configuration to active hunting — on live data.

---

## Links

- **GitHub repository:** *[(https://github.com/kitavim2-commits/windows-sysmon-splunk-siem-lab/new/main)]*

---

*Updated: April 2026 — after first detection fire milestone.*
