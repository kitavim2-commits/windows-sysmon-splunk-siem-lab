# Detection Case Study #4: T1003.001 — LSASS Memory Access

**Lab:** Windows Endpoint Detection Lab  
**Author:** Mitchel Kitavi  
**Date:** 2026-04-26  
**Detection #:** 4 of 4  

---

## 1. Overview

| Field | Detail |
|---|---|
| **Technique** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Tactic** | Credential Access (TA0006) |
| **Data Source** | Sysmon Event ID 10 (ProcessAccess) |
| **MITRE ATT&CK** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| **Severity** | Critical |
| **Platform** | Windows 10/11 |

---

## 2. Technique Background

**LSASS** (Local Security Authority Subsystem Service, `lsass.exe`) is a Windows core process responsible for enforcing security policy and managing authentication. It stores sensitive credential material in memory, including:

- NTLM password hashes
- Kerberos tickets (TGT and service tickets)
- Plaintext passwords (in older configurations)
- LM hashes

Attackers with SYSTEM or Administrator privileges can open a handle to the LSASS process with `PROCESS_VM_READ` permissions and extract this material directly from memory. This is the primary method used by **Mimikatz** (`sekurlsa::logonpasswords`), **ProcDump** (`procdump -ma lsass.exe`), **Cobalt Strike** (built-in hashdump), and virtually every major ransomware operator during the lateral movement phase of an intrusion.

### Real-World Prevalence

LSASS credential dumping is observed in the vast majority of sophisticated intrusions:

- **Ransomware operators** (LockBit, BlackCat, Conti) dump LSASS in the first minutes after gaining admin access to move laterally across the domain
- **Nation-state actors** use custom tools that mimic the same access patterns
- **Red teams** treat this as a standard phase-2 objective immediately after privilege escalation

### Why `GrantedAccess` is the Key Signal

When a process opens a handle to LSASS, Windows records the *access mask* — a bitmask defining what operations are permitted. Sysmon captures this in the `GrantedAccess` field of Event 10. Specific access masks are strongly associated with credential-dumping tools:

| Access Mask | Meaning | Associated Tool |
|---|---|---|
| `0x1410` | VM_READ + QUERY_INFORMATION + QUERY_LIMITED | Mimikatz `sekurlsa` |
| `0x1010` | VM_READ + QUERY_LIMITED | Mimikatz `sekurlsa` variant |
| `0x1438` | VM_READ + QUERY_INFORMATION + DUP_HANDLE | Mimikatz / ProcDump |
| `0x143a` | Extended variant | Mimikatz variants |
| `0x1fffff` | PROCESS_ALL_ACCESS | Broad tools, some AV |
| `0x0040` | VM_READ only | Minimal dumpers |
| `0x1000` | QUERY_LIMITED only | Benign (Windows internals) |

---

## 3. Detection Environment

| Component | Version / Detail |
|---|---|
| OS | Windows 10/11 (home lab) |
| Sysmon | v15.20 |
| Sysmon Config | SwiftOnSecurity + custom ProcessAccess rule |
| SIEM | Splunk Enterprise |
| Sourcetype | `xmlwineventlog` |
| Index | `winlogs` |
| AV | Malwarebytes (primary) + Windows Defender (SxS passive) |

### Sysmon Configuration Note

SwiftOnSecurity's default config includes a `ProcessAccess` rule group set to `onmatch="include"` with **no rules inside it**. Per Sysmon's logic, an include group with no entries logs nothing. Event 10 must be enabled by adding an explicit target rule.

**Custom rule added to `sysmonconfig-export.xml`:**

```xml
<ProcessAccess onmatch="include">
    <!--LSASS credential access detection — T1003.001-->
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
</ProcessAccess>
```

This rule logs Event 10 **only when the target process is lsass.exe** — keeping noise low while capturing exactly the signal needed.

Config reload command:
```powershell
cd C:\Tools
.\Sysmon64.exe -c sysmonconfig-export.xml
```

---

## 4. Simulation

### Method

Real credential-dumping tools (Mimikatz, ProcDump) were **not used** — this is a home lab environment with active AV and no isolated network segment. Instead, the simulation used PowerShell's `Get-Process -Module` flag, which opens a handle to the target process with `PROCESS_VM_READ` permissions to enumerate loaded DLL modules. This produces the **identical Sysmon Event 10 signal** without reading or extracting any credential material.

### Simulation Command

```powershell
# Run from an elevated PowerShell prompt
Get-Process -Name lsass -Module -ErrorAction SilentlyContinue | Out-Null
```

**Why this works as a simulation:**

- `Get-Process -Module` requires `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` — the same access rights Mimikatz uses
- The `GrantedAccess` value captured (`0x1410`) matches the Mimikatz `sekurlsa` access mask exactly
- No credential material is accessed — only the list of loaded DLLs is read
- Sysmon cannot distinguish this handle open from a real attack tool's handle open at the Event 10 level

### Why This is Realistic

From a detection standpoint, this simulation is high-fidelity. Sysmon Event 10 fires on the `OpenProcess()` syscall — at the moment the handle is granted, before any memory read occurs. A real attacker's tool and this simulation look identical at the telemetry layer.

---

## 5. Evidence Captured

### Sysmon Event 10 — Raw Fields

| Field | Value |
|---|---|
| EventCode | 10 |
| SourceImage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| TargetImage | `C:\Windows\system32\lsass.exe` |
| GrantedAccess | `0x1410` |
| access_label | Mimikatz sekurlsa signature |
| CallTrace | `C:\Windows\SYSTEM32\ntdll.dll+9db14\|C:\Windows\System32\KERNELBASE...` |

**Two events captured** — corresponding to two simulation runs. Both show identical access mask `0x1410`.

### False Positives Observed

During baseline collection, two other processes were observed accessing lsass:

| Process | GrantedAccess | Assessment |
|---|---|---|
| `C:\Program Files\Splunk\bin\splunkd.exe` | `0x1fffff` | Splunk process monitoring — known FP, allowlisted |
| `C:\Windows\system32\svchost.exe` | `0x1000` | Windows internal query — benign, allowlisted |

---

## 6. Detection Logic

### Splunk SPL — Detection Query

```spl
index=winlogs sourcetype=xmlwineventlog EventCode=10
| where like(TargetImage, "%lsass.exe")
| where NOT match(SourceImage, "(?i)(splunkd|svchost|MsMpEng|mbam|malwarebytes|csrss|werfault|WerFaultSecure|SecurityHealth|lsass|taskmgr|procexp)")
| eval access_hex=lower(GrantedAccess)
| eval access_label=case(
    access_hex="0x1fffff", "PROCESS_ALL_ACCESS — high suspicion",
    access_hex="0x1438",   "Mimikatz sekurlsa signature",
    access_hex="0x143a",   "Mimikatz variant",
    access_hex="0x1410",   "Mimikatz sekurlsa signature",
    access_hex="0x1010",   "Mimikatz sekurlsa signature",
    access_hex="0x0040",   "PROCESS_VM_READ only",
    true(),                "Unknown mask — review: ".GrantedAccess
  )
| where access_label!="Unknown mask — review: ".GrantedAccess
| table _time, SourceImage, TargetImage, GrantedAccess, access_label, CallTrace
| sort -_time
```

### Query Logic Breakdown

1. **Filter to lsass target** — `TargetImage` contains `lsass.exe`; eliminates all non-relevant Event 10s
2. **Allowlist known-good sources** — excludes Splunk, Windows internals, AV processes by regex
3. **Normalize access mask** — lowercases `GrantedAccess` for consistent matching
4. **Label by attack pattern** — maps known malicious masks to tool associations
5. **Drop unknowns** — removes unlabeled access masks, reducing false positive noise
6. **Surface CallTrace** — preserves forensic stack trace for post-alert investigation

### Verified Result

The query returned exactly 2 events — both `powershell.exe → lsass.exe` with `GrantedAccess: 0x1410`, labeled `Mimikatz sekurlsa signature`. Zero false positives after allowlisting.

---

## 7. MITRE ATT&CK Mapping

```
Tactic:     Credential Access (TA0006)
Technique:  OS Credential Dumping (T1003)
Sub-tech:   LSASS Memory (T1003.001)

Related techniques this detection may also catch:
  T1003.002 — Security Account Manager (SAM dump via lsass handle)
  T1055     — Process Injection (injected code accessing lsass)
```

### Detection Coverage

| Stage | Covered? | Notes |
|---|---|---|
| Handle open (OpenProcess) | ✅ Yes | Event 10 fires at syscall |
| Memory read (ReadProcessMemory) | ❌ No | Requires additional tooling / ETW |
| Dump file write | ❌ No | Needs Event 11 (FileCreate) rule |
| Offline parsing | ❌ No | Out of scope for endpoint |

This detection catches the **handle acquisition** phase — the earliest detectable moment in the credential dumping sequence.

---

## 8. Analyst Response Playbook

When this alert fires in production:

1. **Identify SourceImage** — Is it a known tool? Does the path look legitimate?
2. **Check GrantedAccess** — `0x1410` / `0x1010` / `0x1438` are high-confidence malicious
3. **Review CallTrace** — Unexpected DLLs in the stack (e.g., unsigned, from temp dirs) indicate injection
4. **Check parent process** — What spawned the accessing process? (`Event 1`, `ParentImage`)
5. **Look for dump file** — Search Event 11 for `.dmp` files created within ±60 seconds
6. **Check for lateral movement** — If hashes were dumped, look for pass-the-hash (Event 4624 logon type 3 from unusual sources)
7. **Isolate if confirmed** — Remove endpoint from network before attempting remediation

---

## 9. Sigma Rule

```yaml
title: LSASS Memory Access via Suspicious Process
id: t1003-001-lsass-memory-access
status: experimental
description: Detects non-system processes opening LSASS with memory-read access masks
  associated with credential dumping tools (Mimikatz, ProcDump, etc.)
author: kitavim2-commits
date: 2026-04-26
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
      - '0x143a'
      - '0x1fffff'
  filter_legit:
    SourceImage|contains:
      - '\MsMpEng.exe'
      - '\mbam.exe'
      - '\splunkd.exe'
      - '\csrss.exe'
      - '\werfault.exe'
      - '\svchost.exe'
      - '\lsass.exe'
  condition: selection and not filter_legit
falsepositives:
  - AV/EDR products opening LSASS for process inspection
  - SIEM agents (Splunk, Elastic) querying process information
  - Legitimate admin tools (Process Explorer, Task Manager)
level: high
```

---

## 10. Key Takeaways

- **Event 10 is disabled by default** in SwiftOnSecurity's config — enabling it for lsass alone adds high-value signal with minimal noise
- **`GrantedAccess` is the detection pivot** — the bitmask fingerprints the tool regardless of binary name or path
- **`0x1410` is Mimikatz's primary sekurlsa mask** — seeing this from any non-AV process is a critical alert
- **CallTrace adds forensic depth** — reveals whether the handle was opened by legitimate code or injected shellcode
- **Layered detection is needed** — Event 10 catches the handle open; Event 11 catches the dump file write; both together maximize coverage

---

## 11. Lab Series Navigation

| # | Technique | Event | Status |
|---|---|---|---|
| 1 | T1059.001 — PowerShell Encoded Command | Sysmon Event 1 | ✅ Complete |
| 2 | T1547.001 — Registry Run Key Persistence | Sysmon Event 13 | ✅ Complete |
| 3 | T1071.001 — DNS Beaconing / C2 | Sysmon Event 22 | ✅ Complete |
| 4 | T1003.001 — LSASS Memory Access | Sysmon Event 10 | ✅ Complete |

---

*Part of the [Windows Sysmon + Splunk SIEM Lab](https://github.com/kitavim2-commits/windows-sysmon-splunk-siem-lab)*
