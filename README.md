# 🔍 Windows Endpoint Detection Lab — Sysmon + Splunk SIEM

> A home-built security monitoring stack using Sysmon, Windows native auditing, and Splunk Enterprise to capture, centralize, and hunt through endpoint telemetry. Includes live detection validation against simulated adversary techniques (MITRE ATT&CK).

![Status](https://img.shields.io/badge/status-operational-brightgreen)
![Detection](https://img.shields.io/badge/first%20detection-fired-success)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)
![Splunk](https://img.shields.io/badge/Splunk-Enterprise-orange)
![Sysmon](https://img.shields.io/badge/Sysmon-v15.20-lightgrey)
![ATT&CK 1](https://img.shields.io/badge/MITRE%20ATT%26CK-T1059.001-red)
![ATT&CK 2](https://img.shields.io/badge/MITRE%20ATT%26CK-T1547.001-red)
![ATT&CK 3](https://img.shields.io/badge/MITRE%20ATT%26CK-T1071.001-red)
---

## 📸 Visual Evidence

### Detection Fire — T1059.001 (PowerShell Encoded Command)
Live detection of an adversary-style encoded PowerShell command, with full field extraction via the Splunk Add-on for Microsoft Sysmon. Time, user, parent process, image, and command line all captured cleanly — exactly what a SOC analyst would see in production.

![Detection Fire](https://raw.githubusercontent.com/kitavim2-commits/windows-sysmon-splunk-siem-lab/main/screenshots/01-detection-fire-clean.png)

### Data Ingestion Pipeline
Four Windows log sources flowing into the dedicated `winlogs` index: Security, System, Application, and Sysmon Operational.

![Data Sources](https://raw.githubusercontent.com/kitavim2-commits/windows-sysmon-splunk-siem-lab/main/screenshots/04-data-sources.png)

### Sysmon Generating Events at the OS Layer
Sysmon Operational log in Event Viewer, showing Event ID 1 (process creation) entries being captured at the kernel level before forwarding to Splunk.

![Sysmon Event Viewer](https://raw.githubusercontent.com/kitavim2-commits/windows-sysmon-splunk-siem-lab/main/screenshots/03-sysmon-event-viewer.png)

### Splunk Add-on for Sysmon Installed
The Splunk Add-on for Microsoft Sysmon enables proper field extraction (Image, CommandLine, ParentImage, etc.) from Sysmon's XML event format.

![Sysmon Add-on](https://raw.githubusercontent.com/kitavim2-commits/windows-sysmon-splunk-siem-lab/main/screenshots/02-sysmon-addon-installed.png)

### Detection Fire — T1547.001 (Registry Run Key Persistence)
Sysmon Event ID 13 caught a benign persistence simulation: a Registry Run key planted via PowerShell pointing to `notepad.exe`. Detection captured the writer process, full registry path, target executable, and user — everything needed for SOC triage.

![T1547 Detection Fire](https://raw.githubusercontent.com/kitavim2-commits/windows-sysmon-splunk-siem-lab/main/screenshots/05-detection-fire-T1547-persistence.png)

### Detection Fire — T1071.001 (DNS Beaconing / C2)
Statistical detection of beacon-style DNS traffic: 20 queries with unique subdomains under a single suspicious `.xyz` parent domain over ~60 seconds. PowerShell as the originating process. The 1:1 count-to-unique-subdomains ratio is the smoking gun.

![T1071 Detection Fire](https://raw.githubusercontent.com/kitavim2-commits/windows-sysmon-splunk-siem-lab/main/screenshots/07-%20T1071-beaconing.png)

---

## 📋 Project Overview

This project stands up a fully functional endpoint detection lab on a single Windows host. It captures rich process, network, and file telemetry from the operating system, forwards it into a local Splunk instance, and validates detection logic against real adversary behavior simulated via Atomic Red Team and manual technique execution.

The lab demonstrates, in a portfolio-ready way, the core SOC analyst workflow: **enable logging → centralize → search → detect → simulate → verify → tune.**

### Core Objectives (Complete ✅)

- [x] Enable Windows native process-creation auditing (Event ID 4688) with command line logging
- [x] Deploy Sysmon with a tuned configuration for enriched endpoint telemetry
- [x] **Detect adversary persistence (T1547.001 — Registry Run Key)** 🆕
- [x] Install and configure Splunk Enterprise as a local SIEM
- [x] Ingest Windows Security, System, Application, and Sysmon logs into a dedicated index
- [x] Install Atomic Red Team for adversary simulation
- [x] **Generate adversary telemetry and successfully detect it in Splunk** 🎯
- [x] Document the workflow for reproducibility and portfolio use
- [x] **Detect adversary C2 beaconing (T1071.001 — DNS)** 🆕

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows 10/11 Endpoint                    │
│                                                              │
│  ┌──────────────────┐         ┌──────────────────────┐      │
│  │  Windows Native  │         │       Sysmon         │      │
│  │  Audit Policy    │         │  (SwiftOnSecurity    │      │
│  │  (Event 4688)    │         │   config)            │      │
│  └────────┬─────────┘         └──────────┬───────────┘      │
│           │                              │                   │
│           ▼                              ▼                   │
│  ┌──────────────────────────────────────────────────┐       │
│  │         Windows Event Log Subsystem              │       │
│  │   Security │ System │ Application │ Sysmon/Op   │       │
│  └──────────────────────┬───────────────────────────┘       │
│                         │                                    │
│                         ▼                                    │
│  ┌──────────────────────────────────────────────────┐       │
│  │         Splunk Enterprise (localhost)            │       │
│  │              Index: winlogs                      │       │
│  │           Search & Reporting App                 │       │
│  └──────────────────────┬───────────────────────────┘       │
│                         │                                    │
│                         ▼                                    │
│  ┌──────────────────────────────────────────────────┐       │
│  │         Detection Queries (SPL)                  │       │
│  │    Mapped to MITRE ATT&CK techniques             │       │
│  └──────────────────────────────────────────────────┘       │
│                         ▲                                    │
│                         │                                    │
│  ┌──────────────────────┴───────────────────────────┐       │
│  │     Atomic Red Team / Manual Adversary Sim       │       │
│  │         (TTP generation for validation)          │       │
│  └──────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

| Component | Version | Purpose |
|---|---|---|
| Windows 10/11 | — | Host operating system |
| Sysmon | 15.20 | Enhanced endpoint telemetry |
| SwiftOnSecurity Sysmon Config | latest | Community-tuned baseline configuration |
| Splunk Enterprise | 9.x | Log aggregation, indexing, search |
| Atomic Red Team | latest | MITRE ATT&CK-mapped adversary simulation |
| Windows Event Log | native | Source for Security, System, Application events |
| PowerShell | 5.1+ | Configuration automation and verification |

---

## 🔧 Build Phases

### Phase 1 — Enable Windows Native Process Auditing

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### Phase 2 — Deploy Sysmon

```powershell
cd C:\Tools
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile "sysmonconfig-export.xml"
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### Phase 3 — Install Splunk Enterprise

- Installed Splunk Enterprise (Windows MSI)
- Created dedicated index: `winlogs`

### Phase 4 — Configure Splunk Inputs

Windows logs via GUI; Sysmon added via manual `inputs.conf` edit:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = winlogs
renderXml = true
```

### Phase 5 — Validate Data Flow

```spl
index=winlogs earliest=-30m | stats count by source
```

**Results:**
| Source | Event Count (30 min) |
|---|---|
| `WinEventLog:Security` | 3,021 |
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | 2,609 |
| `WinEventLog:System` | 43 |

### Phase 6 — Install Atomic Red Team

Added folder exclusion for `C:\AtomicRedTeam` in Malwarebytes (primary AV; Defender in SxS Passive Mode), then installed framework:

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

### Phase 7 — Adversary Simulation & First Detection Fire 🎯

**Decision:** Reviewed Atomic tests with `-ShowDetails` before execution. Available T1059.001 tests required external downloads (Mimikatz, BloodHound, PowerSploit) or framework dependencies. Rather than deploy real offensive tools, executed the core technique manually — equivalent TTP, minimal risk.

**Test executed:**
```powershell
powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAZgByAG8AbQAgAHQAaABlACAAYQB0AHQAYQBjAGsAZQByACIA
```

Base64 decodes to: `Write-Host "Hello from the attacker"`

**MITRE ATT&CK mapping:**
- T1059.001 — Command and Scripting Interpreter: PowerShell
- T1027 — Obfuscated Files or Information

**Detection query (raw-text fallback for XML-encoded Sysmon events):**
```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
  powershell.exe EncodedCommand
```

**Result: ✅ 1 event matched — detection fired within seconds.** Full event captured:

- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine: full encoded command visible
- ParentImage / ParentCommandLine (process tree intact)
- User: `DESKTOP-SKETBJN\<user>`
- File hashes: MD5, SHA256, IMPHASH
- ProcessGuid, ParentProcessGuid (correlation IDs)
- IntegrityLevel: High

### Bonus — Authentic Incident Response Exercise

After accidentally triggering ATR Test #1 (Mimikatz) without fully reviewing it, performed impact analysis using SIEM forensic queries:

```spl
# Did any PowerShell download cradle run?
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
  CommandLine="*DownloadString*"
```
**Result:** 0 events.

```spl
# Did the host connect to GitHub to fetch the payload?
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
  (DestinationHostname="*githubusercontent*" OR DestinationHostname="*raw.github*")
```
**Result:** 0 events.

Confirmed the download was blocked upstream — the test never executed. This became an authentic incident-response drill: **identify → query SIEM → confirm scope → document → cleanup.**

---

## 🕵️ Detection Queries

### Encoded PowerShell Commands (T1059.001, T1027) — VERIFIED ✅

```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
  Image="*powershell.exe" 
  (CommandLine="*-EncodedCommand*" OR CommandLine="*-Enc *" OR CommandLine="*-e *")
```

### Office Applications Spawning Command Shells (T1566.001)

```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
  (ParentImage="*winword.exe" OR ParentImage="*excel.exe" 
   OR ParentImage="*powerpnt.exe" OR ParentImage="*outlook.exe")
  (Image="*cmd.exe" OR Image="*powershell.exe" 
   OR Image="*wscript.exe" OR Image="*cscript.exe")
```

### LOLBIN Abuse — certutil Downloads (T1105)

```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
  Image="*certutil.exe" 
  (CommandLine="*urlcache*" OR CommandLine="*-f *http*")
```

### Suspicious Network Connections from Scripting Engines

```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
  (Image="*powershell.exe" OR Image="*cscript.exe" OR Image="*wscript.exe")
| table _time Image DestinationIp DestinationHostname
```

### Incident-Response Search — Download Cradle Detection

```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
  CommandLine="*DownloadString*"
```

### Processes Running from User Temp Directories (T1036)

```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
  (Image="*\\AppData\\Local\\Temp\\*" OR Image="*\\AppData\\Roaming\\*")
| table _time User Image CommandLine ParentImage
```

### Failed Logon Attempts (T1110)

```spl
index=winlogs EventCode=4625 
| stats count by Account_Name, Workstation_Name, Source_Network_Address
| sort -count
```
### T1547.001 — Registry Run Key Persistence — VERIFIED ✅

```spl
index=winlogs sourcetype=xmlwineventlog EventCode=13 
  (TargetObject="*\\CurrentVersion\\Run\\*" 
   OR TargetObject="*\\CurrentVersion\\RunOnce\\*")
| table _time User Image TargetObject Details
| sort -_time
```

See full case study: [`docs/case-studies/T1547-001-persistence-registry-runkey.md`](docs/case-studies/T1547-001-persistence-registry-runkey.md)

---
### T1071.001 — DNS Beaconing — VERIFIED ✅

Statistical detection looking for high count-to-unique-subdomains ratios on a single parent domain from a single process — the classic DNS tunneling/beacon fingerprint.

```spl
index=winlogs sourcetype=xmlwineventlog EventCode=22 earliest=-10m
| rex field=QueryName "(?<parent_domain>[^.]+\.[^.]+)$"
| stats count, dc(QueryName) as unique_subdomains, min(_time) as first_seen, max(_time) as last_seen by parent_domain, Image
| eval duration_sec = last_seen - first_seen
| where count >= 10 AND unique_subdomains >= 5
| sort -count
```

See full case study: [`docs/case-studies/T1071-001-dns-beaconing.md`](docs/case-studies/T1071-001-dns-beaconing.md)

---
## 🎯 Key Event IDs Reference

| Event ID | Source | Meaning |
|---|---|---|
| 4688 | Windows Security | Process creation (native) |
| 4625 | Windows Security | Failed logon |
| 4624 | Windows Security | Successful logon |
| Sysmon 1 | Sysmon Operational | Process creation (enriched) |
| Sysmon 3 | Sysmon Operational | Network connection |
| Sysmon 7 | Sysmon Operational | Image / DLL loaded |
| Sysmon 10 | Sysmon Operational | Process access |
| Sysmon 11 | Sysmon Operational | File created |
| Sysmon 22 | Sysmon Operational | DNS query |

---

## 🧠 Lessons Learned

- **PowerShell requires explicit `.\` prefixing** — early stumbling block that reinforced good secure-execution habits.
- **Notepad must be run as Administrator** to edit files under `C:\Program Files\`. Silent save failures led me to bypass Notepad entirely with `Add-Content` from elevated PowerShell — faster and more reliable.
- **Splunk `btool`** is indispensable for verifying which config files are in effect: `splunk btool inputs list --debug` confirmed the effective source of each stanza.
- **Sysmon's log path** (`Microsoft-Windows-Sysmon/Operational`) is not in Splunk's default GUI dropdown — it must be added via `inputs.conf`.
- **`renderXml = true` without the Splunk Sysmon Add-on** leaves fields un-extracted — values like `Image` and `CommandLine` live inside XML attributes rather than as searchable fields. Either install the add-on or search raw event text.
- **Always run `-ShowDetails` before executing Atomic Red Team tests.** Test numbering has no relationship to safety — Test #1 under T1059.001 is Mimikatz.
- **Defense in depth saved me.** After accidentally triggering a Mimikatz test, forensic SIEM queries confirmed the download was blocked. This became an authentic IR drill — exactly the workflow used in real investigations.
- **On systems running third-party AV**, Microsoft Defender enters SxS Passive Mode. `Add-MpPreference` calls fail with `0x800106ba` because the active AV (Malwarebytes here) is the decision-maker for exclusions.

---

## 🚀 Roadmap

- [x] Stand up logging and SIEM
- [x] Validate first detection against simulated TTP
- [ ] Install **Splunk Add-on for Microsoft Sysmon** for clean field extraction
- [ ] Build a **Splunk dashboard** for real-time endpoint visibility
- [ ] Run a broader Atomic Red Team campaign (T1003 credential access, T1547 persistence) and validate detections
- [ ] Author **Sigma rules** for each detection and convert to SPL
- [ ] Deploy a **Universal Forwarder** to a second VM for multi-host ingestion
- [ ] Integrate **threat intelligence feeds** (MISP, OTX IOCs) via Splunk lookups
- [ ] Move to **Olaf Hartong's modular Sysmon config** for more granular tuning
- [ ] Save the validated detection set as scheduled **Splunk alerts**

---

## 📚 References & Resources

- [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Olaf Hartong Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam)
- [SigmaHQ Detection Rules](https://github.com/SigmaHQ/sigma)
- [Ultimate Windows Security Event Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Splunk Documentation](https://docs.splunk.com/)

---

## 📝 License

Personal homelab build for educational purposes. Referenced tools and configurations retain their respective licenses.

---

*Built as part of a hands-on SOC analyst learning path. From "what is Event ID 4688?" to first live detection fire — documented end-to-end.*
