# T1003.001 — OS Credential Dumping: LSASS Memory

**Detection #4 — LSASS Process Access via Sysmon Event 10**

---

## Summary

This case study documents the detection of credential dumping attempts targeting LSASS (Local Security Authority Subsystem Service) using Sysmon Event ID 10 (process access) ingested into Splunk. The detection identifies non-system processes opening handles to `lsass.exe` with access masks associated with memory-read operations — the specific permissions required by credential dumping tools including Mimikatz (`sekurlsa::logonpasswords`), ProcDump (`procdump -ma lsass.exe`), Cobalt Strike, and Sliver.

| Field | Value |
|---|---|
| **MITRE ATT&CK** | [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| **Related** | T1003.002 — SAM, T1055 — Process Injection |
| **Data source** | Sysmon Event ID 10 (process access) |
| **Log index** | `winlogs` |
| **Sourcetype** | `xmlwineventlog` |
| **Detection type** | Behavioral / access mask signature |

---

## Why this matters

LSASS is the Windows process responsible for authentication policy enforcement. It holds in memory:

- NTLM password hashes for all interactively logged-on users
- Kerberos tickets (TGTs and service tickets)
- Plaintext credentials in some configurations (WDigest)
- LM hashes (legacy systems)

Any process with SYSTEM or Administrator privileges can call `OpenProcess()` against LSASS with `PROCESS_VM_READ` permissions and extract this material directly. This is the primary lateral movement enabler in the majority of ransomware intrusions — operators dump LSASS within minutes of gaining admin access to harvest hashes for pass-the-hash or offline cracking across the domain.

The critical forensic detail is that Sysmon Event 10 fires at the `OpenProcess()` syscall — **before any memory read occurs**. This means the detection triggers at the earliest possible moment in the attack chain, before any credentials are actually extracted.

---

## Lab environment

| Component | Version |
|---|---|
| OS | Windows 10/11 |
| Sysmon | 15.20 (schema 4.91) |
| Sysmon config | SwiftOnSecurity baseline (modified — see below) |
| SIEM | Splunk Enterprise |
| Splunk Add-on | Splunk Add-on for Microsoft Sysmon |

---

## Lab gotcha: Event 10 is disabled by default in SwiftOnSecurity's config

This detection required a config change before any telemetry appeared. SwiftOnSecurity's config includes a `ProcessAccess` RuleGroup but it is intentionally empty:

```xml
<ProcessAccess onmatch="include">
    <!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
</ProcessAccess>
```

In Sysmon, an `onmatch="include"` group with no rules inside it logs **nothing** — the comment says exactly this. Event 10 is disabled by design in the baseline config because process access monitoring on a busy system is extremely noisy: every AV scan, backup agent, and debugger opens handles constantly.

**Symptom:** Zero results from `index=winlogs sourcetype=xmlwineventlog EventCode=10` even after running the simulation, confirmed by checking the config:

```powershell
Select-String -Path "C:\Tools\sysmonconfig-export.xml" -Pattern "ProcessAccess" -Context 0,3
```

Which returned:

```
<ProcessAccess onmatch="include">
    <!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
</ProcessAccess>
```

**Fix:** Replace the empty block with a targeted include rule for lsass.exe:

```xml
<ProcessAccess onmatch="include">
    <!--LSASS credential access detection — T1003.001-->
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
</ProcessAccess>
```

Reload with:

```powershell
cd C:\Tools
.\Sysmon64.exe -c sysmonconfig-export.xml
```

**Why this rule design is correct:** Targeting only `lsass.exe` as the `TargetImage` keeps the event volume low while capturing the exact signal needed — any process opening a handle to lsass. The noise problem that motivated disabling Event 10 entirely doesn't apply when the filter is this specific.

### Lessons

- **Read the comments in the config.** SwiftOnSecurity documented this behavior explicitly — the empty include group is intentional, not an oversight.
- **"Configuration updated" does not mean events are flowing.** Sysmon validates and loads the config without verifying whether any rules would actually fire. Always verify with a test query after every config change.
- **Targeted include rules beat broad exclude rules for high-noise event types.** For Event 10, one specific TargetImage is more useful than trying to exclude everything else.

---

## Simulation

Real credential-dumping tools (Mimikatz, ProcDump) were not used — this is a home lab with active AV and no isolated network segment. Instead, PowerShell's `Get-Process -Module` flag was used as a safe simulation.

```powershell
# Run from an elevated PowerShell prompt
# Opens a PROCESS_VM_READ handle to lsass to enumerate loaded modules
# Does NOT read or extract any credential material
Get-Process -Name lsass -Module -ErrorAction SilentlyContinue | Out-Null
```

**Why this is a valid simulation:** `Get-Process -Module` calls `OpenProcess()` with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` — the same access rights Mimikatz requests. Sysmon Event 10 fires on the `OpenProcess()` call before any memory read occurs, so the telemetry generated is identical to a real credential dumping attempt. The `GrantedAccess` value captured (`0x1410`) matches Mimikatz's primary `sekurlsa` access mask exactly.

**Safety:** No credential material is read. `Get-Process -Module` only enumerates the list of DLLs loaded in the target process — it does not read LSASS memory buffers.

---

## Detection logic

### Splunk SPL

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

### How it works

| Step | Purpose |
|---|---|
| `EventCode=10` | Filter to process access events only |
| `where like(TargetImage, "%lsass.exe")` | Narrow to events targeting LSASS specifically |
| `where NOT match(SourceImage, ...)` | Allowlist known-good processes that legitimately open LSASS handles |
| `eval access_hex` | Normalize GrantedAccess to lowercase hex for consistent matching |
| `eval access_label` | Map known malicious access masks to tool associations |
| `where access_label != "Unknown..."` | Drop events with unlabeled masks — reduces noise from benign processes not caught by the allowlist |
| `CallTrace` | Preserved in output — forensic stack trace showing exactly how the handle was opened |

### The key field: GrantedAccess

When a process calls `OpenProcess()`, Windows records the access mask — a bitmask defining what operations are permitted on the handle. Sysmon captures this in `GrantedAccess`. Specific masks fingerprint the tool regardless of binary name or path, making name-based evasion ineffective:

| Mask | Meaning | Associated tool |
|---|---|---|
| `0x1410` | VM_READ + QUERY_INFORMATION + QUERY_LIMITED | Mimikatz `sekurlsa` (primary) |
| `0x1010` | VM_READ + QUERY_LIMITED | Mimikatz `sekurlsa` (variant) |
| `0x1438` | VM_READ + QUERY_INFORMATION + DUP_HANDLE | Mimikatz / ProcDump |
| `0x143a` | Extended variant | Mimikatz variants |
| `0x1fffff` | PROCESS_ALL_ACCESS | Broad tools, some AV/monitoring |
| `0x0040` | VM_READ only | Minimal custom dumpers |
| `0x1000` | QUERY_LIMITED only | Benign — Windows internals |

### CallTrace: the forensic bonus

`CallTrace` records the full call stack at the moment `OpenProcess()` was invoked — which DLLs were involved, in what order. This field distinguishes a legitimate process that was injected with shellcode (the trace will show an unexpected or unsigned DLL mid-stack) from a legitimate process doing a legitimate thing (clean system DLL chain). For LSASS access specifically, `ntdll.dll → KERNELBASE.dll → [tool DLL]` is normal; anything else in the stack warrants deeper investigation.

---

## Results

Running the simulation (`Get-Process -Name lsass -Module`) generated two Event 10 entries — one per simulation run. The detection SPL returned exactly those two events with zero false positives after allowlisting:

| _time | SourceImage | TargetImage | GrantedAccess | access_label |
|---|---|---|---|---|
| 2026-04-26 19:14:29 | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `C:\Windows\system32\lsass.exe` | `0x1410` | Mimikatz sekurlsa signature |
| 2026-04-26 19:11:53 | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `C:\Windows\system32\lsass.exe` | `0x1410` | Mimikatz sekurlsa signature |

`powershell.exe` opening a handle to `lsass.exe` with access mask `0x1410` — the Mimikatz sekurlsa signature — is a high-confidence signal. A real attacker using Mimikatz, a renamed Mimikatz binary, or any tool that calls `sekurlsa::logonpasswords` would produce an identical event.

**False positives identified during baseline collection:**

| Process | GrantedAccess | Assessment |
|---|---|---|
| `C:\Program Files\Splunk\bin\splunkd.exe` | `0x1fffff` | Splunk process monitoring — added to allowlist |
| `C:\Windows\system32\svchost.exe` | `0x1000` | Windows internal query — benign, added to allowlist |

*(See `screenshots/08-T1003-lsass-event10.png`.)*

---

## Tuning for production

The allowlist in the detection query is a starting point, not a complete list. Every environment will have additional legitimate processes that open LSASS handles:

| Source | Why it accesses LSASS |
|---|---|
| AV / EDR agents (MsMpEng, mbam, CrowdStrike, SentinelOne) | Process memory scanning for malware detection |
| SIEM / monitoring agents (Splunk, Elastic, NXLog) | Process enumeration for telemetry |
| Password managers | Some products verify credential store integrity |
| Remote access tools (RDP, VDI agents) | Session credential handling |
| Vulnerability scanners | Host assessment |

**Recommended production approach:**

- Audit Event 10 events targeting lsass over a 7-day baseline window to identify all legitimate `SourceImage` values in your environment
- Maintain the allowlist as a Splunk lookup table rather than hardcoded regex — easier to update without modifying the query
- Alert on `0x1fffff` (PROCESS_ALL_ACCESS) from any process not on the allowlist — this is never a routine access level for lsass
- Correlate with Event 11 (file created) looking for `.dmp` files within ±60 seconds — if a handle open is followed by a dump file write, confidence goes to critical
- Correlate downstream with Windows Security Event 4624 logon type 3 from unusual sources to detect pass-the-hash following a successful dump

---

## Limitations

1. **This detection catches the handle open, not the memory read.** If an attacker uses a driver or kernel exploit to read LSASS memory without calling `OpenProcess()` at user-mode, Event 10 will not fire. Kernel-level dumping techniques (e.g., direct syscalls bypassing `ntdll.dll` hooks) may also evade this.
2. **Protected Process Light (PPL) partially mitigates this at the OS level.** Windows 8.1+ allows LSASS to run as a Protected Process Light, which prevents standard `OpenProcess()` calls from succeeding even with admin rights. PPL bypass techniques exist but they are significantly more complex and leave different artifacts.
3. **Dump file write is not covered here.** A full detection chain should also monitor Event 11 for `.dmp` file creation, which catches tools that dump to disk for offline parsing (ProcDump, comsvcs.dll via rundll32).
4. **The allowlist requires maintenance.** New software installs, agent upgrades, and configuration changes can introduce new legitimate LSASS-accessing processes that generate false positives until added to the allowlist.

---

## References

- MITRE ATT&CK — [T1003.001 OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- Microsoft Sysinternals — [Sysmon documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- SwiftOnSecurity — [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (baseline configuration)
- Gentilkiwi — [Mimikatz](https://github.com/gentilkiwi/mimikatz) (reference for access mask values)
- SANS — [Detecting Credential Dumping](https://www.sans.org/white-papers/credential-dumping-windows/)

---

## Files in this case study

| File | Purpose |
|---|---|
| `docs/case-studies/T1003.001-LSASS-Memory-Access.md` | This document |
| `screenshots/08-T1003-lsass-event10.png` | Splunk result showing powershell.exe → lsass.exe, GrantedAccess 0x1410 |

---

*Detection #4 of an ongoing endpoint detection lab. See [repo root](../../) for full project context.*
