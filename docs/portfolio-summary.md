# Mitchel Kitavi SOC Analyst Portfolio Summary

## Project: Windows Endpoint Detection Lab — Sysmon + Splunk SIEM with Adversary Simulation

**Status:** Operational · **Role:** Solo · **Duration:** 2 sessions

---

## Elevator Pitch (30 seconds)

> Built an end-to-end endpoint detection lab: Sysmon for telemetry, Splunk Enterprise as the SIEM, Atomic Red Team for adversary simulation. Enabled native Windows process auditing (Event 4688 with command-line logging), deployed Sysmon with a production-grade config, centralized ~7,000 events into a dedicated Splunk index, and wrote SPL detections mapped to MITRE ATT&CK. Then I validated it the right way — by executing simulated attacks and confirming my SIEM caught them. Including an unplanned incident-response exercise where a Mimikatz atomic test fired accidentally; used SIEM forensic queries to confirm the download was blocked and no compromise occurred. Every stage of the SOC detection workflow, demonstrated on live data.

---

## Resume Bullets (Drop-in Ready)

**Single-bullet summary:**
- Built a Windows endpoint detection lab using Sysmon and Splunk Enterprise; configured native auditing (Event ID 4688 with command-line logging), deployed Sysmon with SwiftOnSecurity config, installed Atomic Red Team for MITRE ATT&CK-mapped simulation, authored SPL detections (T1059, T1566, T1105, T1036), and validated the pipeline by generating adversary telemetry and confirming detection fire for T1059.001 (PowerShell encoded command).

**Multi-bullet detail:**
- Deployed **Sysmon 15.20** with SwiftOnSecurity's community config to capture enriched process, network, file, and DNS telemetry on a Windows 10/11 endpoint.
- Stood up **Splunk Enterprise** with a dedicated `winlogs` index, configuring four Windows Event Log inputs (Security, System, Application, Sysmon Operational) via a combination of GUI and manual `inputs.conf` editing verified with `splunk btool`.
- Enabled native **Windows process-creation auditing** (Event ID 4688) with command-line logging via `auditpol` and registry modification.
- Installed **Atomic Red Team** and executed benign adversary simulations for MITRE ATT&CK T1059.001 (PowerShell encoded command execution) after reviewing each test with `-ShowDetails` to confirm safety.
- **Validated detection pipeline end-to-end** by generating telemetry for a base64-encoded PowerShell execution and confirming capture via SPL detection query — first detection fire achieved with full forensic context (hashes, ProcessGuid, parent command line, integrity level).
- **Performed authentic incident response** after a Mimikatz atomic test triggered unexpectedly: queried Sysmon network and process data to confirm the download cradle was blocked, documented the exercise, and cleaned up artifacts — a realistic IR workflow.
- Diagnosed and resolved SIEM issues including raw-XML Sysmon ingestion (Splunk Add-on for Sysmon not yet installed) and third-party AV interaction with Microsoft Defender in SxS Passive Mode.

---

## Skills Demonstrated

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

## Talking Points for Interviews

### Q: Why 4688 AND Sysmon? Aren't they redundant?
> They overlap but Sysmon is significantly richer. 4688 gives you process name, parent name, user, and (if enabled) command line. Sysmon Event 1 adds file hashes (MD5/SHA256/IMPHASH), parent command line (not just the name), current directory, integrity level, and a unique ProcessGuid for cross-event correlation. For detection engineering Sysmon wins, but 4688 is native on domain systems, so knowing both matters.

### Q: Walk me through how you validated your detections.
> I didn't just write queries and trust them. I installed Atomic Red Team, reviewed tests with `-ShowDetails` before running any of them — that's critical, Atomic Test #1 for T1059.001 is literal Mimikatz — and then executed a benign encoded PowerShell command to simulate the obfuscation technique. Ran my detection query in Splunk, confirmed the event fired within seconds with full forensic context. If the query hadn't matched, I'd tune until it did, then test for false positives against normal activity. That's the detect-simulate-verify-tune loop.

### Q: Tell me about a time things went sideways.
> I ran an Atomic Red Team test without reading the details carefully and it turned out to be Mimikatz. Instead of panicking, I used my SIEM to do real incident response — queried for `DownloadString` in process command lines to check if the cradle ran, queried Sysmon Event 3 for network connections to `githubusercontent.com` to see if the payload was pulled. Both came back empty, which confirmed the download was blocked upstream by Malwarebytes. I documented the exercise, ran the Atomic cleanup command, and kept going. Honestly, it was more valuable than a clean session would have been — I got to practice authentic IR triage on my own box.

### Q: What's your detection philosophy?
> Start from MITRE ATT&CK and pick techniques your environment is most exposed to. Write a detection, generate telemetry that should trigger it, verify the fire, then tune against normal activity to suppress false positives. A detection that's 100% accurate but never runs is useless; one that fires constantly gets ignored. Calibrate against real data, not theory.

### Q: What was your biggest troubleshooting win?
> Sysmon events were indexed but my field-based detections weren't firing. Turned out `renderXml = true` in `inputs.conf` was storing events as raw XML blobs without field extraction because I hadn't installed the Splunk Add-on for Sysmon. Diagnosed by searching raw event text — that found the event, which proved data was flowing, which told me the problem was parsing not ingestion. Workaround: search XML text directly. Proper fix: install the Sysmon add-on, which makes all fields natively searchable. Classic "the data is there, the extractor isn't" situation.

### Q: What's next for the lab?
> Splunk Add-on for Sysmon so field extraction is clean, then a dashboard for real-time visibility, then broader ATT&CK coverage — credential access (T1003) and persistence (T1547) are the next targets. I also want to author Sigma rules so my detections are portable across SIEMs, and eventually add a second host with a Universal Forwarder to simulate multi-endpoint correlation.

---

## Links

- **GitHub repository:** *[add your repo URL](https://github.com/kitavim2-commits/windows-sysmon-splunk-siem-lab/new/main)*

---

*Updated: April 2026 — after first detection fire milestone.*
