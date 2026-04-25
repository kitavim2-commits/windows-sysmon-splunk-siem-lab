# Detection Case Study: PowerShell Encoded Command Execution

**Date:** April 23, 2026  
**Analyst:** Mitchel Kitavi 
**Environment:** Windows 10/11 endpoint with Sysmon + Splunk Enterprise SIEM  
**Status:** Detection validated ✅

---

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | TA0002 — Execution; TA0005 — Defense Evasion |
| Technique | T1059.001 — Command and Scripting Interpreter: PowerShell |
| Sub-technique | T1027 — Obfuscated Files or Information |
| Platform | Windows |
| Data Source | Process creation (Sysmon Event ID 1 / Windows Event ID 4688) |

---

## Attack Technique

Adversaries frequently use Base64-encoded PowerShell commands to evade string-based detections and hide intent. The `-EncodedCommand` (or `-Enc` / `-e`) parameter accepts a UTF-16LE Base64-encoded script, which PowerShell decodes and executes at runtime.

**Why attackers use it:**
- Bypasses simple signature-based detections that look for known bad strings
- Hides command purpose from casual log review
- Allows arbitrary scripts to be passed via single command lines (fits into scheduled tasks, macros, etc.)
- Works in any default PowerShell session without configuration changes

**Real-world prevalence:** Used by Emotet, Qakbot, Cobalt Strike beacons, and nearly every commodity malware family that deploys PowerShell payloads.

---

## Simulation

**Executed in an elevated PowerShell session on the endpoint:**

```powershell
powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAZgByAG8AbQAgAHQAaABlACAAYQB0AHQAYQBjAGsAZQByACIA
```

**Decoded payload** (retrieved via analyst decoding, simulating real triage):
```powershell
Write-Host "Hello from the attacker"
```

**Payload verification command** (for the analyst):
```powershell
[System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String("VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAZgByAG8AbQAgAHQAaABlACAAYQB0AHQAYQBjAGsAZQByACIA")
)
```

**Observed behavior:** `"Hello from the attacker"` printed to the console. No files written, no persistence, no network activity. Pure technique simulation.

---

## Detection Query

**Primary detection (field-based — requires Splunk Add-on for Sysmon for clean extraction):**

```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
  Image="*powershell.exe" 
  (CommandLine="*-EncodedCommand*" OR CommandLine="*-Enc *" OR CommandLine="*-e *")
| table _time User ParentImage Image CommandLine
| sort -_time
```

**Fallback detection (raw-text — works without Sysmon add-on):**

```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
  powershell.exe EncodedCommand
```

**Why the fallback was needed:** In this lab, Sysmon events were ingested with `renderXml = true` in `inputs.conf`, but without the Splunk Add-on for Microsoft Sysmon installed, the XML attributes (`Name='Image'`, `Name='CommandLine'`, etc.) were not parsed into searchable fields. The raw-text fallback matches the string representation of these values inside the event XML. A proper deployment would install the Sysmon add-on to enable native field extraction.

---

## Detection Result

**Matched events:** 1  
**Detection latency:** Seconds (Sysmon → Windows Event Log → Splunk input → index)

### Captured Event Details

| Field | Value |
|---|---|
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| CommandLine | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand VwByAGkA...` |
| ParentImage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| User | `DESKTOP-SKETBJN\<user>` |
| IntegrityLevel | High |
| ProcessGuid | `{db871195-0599-69eb-4826-000000003000}` |
| ParentProcessId | 15208 |
| MD5 | `2E5A8590CF6848968FC23DE3FA1E25F1` |
| SHA256 | `9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3` |
| IMPHASH | `3D08F4848535206D772DE145804FF4B6` |

All fields necessary for triage, pivot, and reporting were captured.

---

## Tuning Considerations

The detection is intentionally broad — any `powershell.exe` process with `-EncodedCommand`, `-Enc`, or `-e` in the command line triggers it. In a production environment, expect false positives from:

| Source | Why it triggers | Handling |
|---|---|---|
| Microsoft Intune / MDM | Uses encoded commands for configuration enforcement | Exclude by ParentImage or MDM-specific command patterns |
| PDQ Deploy, ConnectWise Automate | RMM tools frequently use encoded PowerShell | Exclude by deploying host or parent process |
| SCCM / ConfigMgr | Runs encoded commands during client health actions | Exclude by known SCCM parent processes |
| Internal automation scripts | Dev teams sometimes base64 encode for convenience | Exclude by known script paths; educate developers |

**Recommended tuning additions:**
- Filter out encoded commands that decode to known-benign patterns (use SPL to decode inline and match against allowlist)
- Alert on encoded commands that ALSO make network connections within 60 seconds (stronger signal of malicious intent)
- Separate low-confidence and high-confidence detection tiers

---

## Secondary Detections Tested

During this exercise, related detections were also validated against real telemetry:

### Download Cradle Detection (T1105)
```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
  CommandLine="*DownloadString*"
```
**Use case:** Confirmed a Mimikatz atomic test did not execute (query returned 0 events, proving the `IEX (New-Object Net.WebClient).DownloadString(...)` cradle was blocked upstream).

### Suspicious Network Connection (T1071.001)
```spl
index=winlogs source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 
  (DestinationHostname="*githubusercontent*" OR DestinationHostname="*raw.github*")
```
**Use case:** Verified no outbound connections to common payload-hosting infrastructure during the IR exercise.

---

## Incident Response Workflow Demonstrated

When an unplanned Mimikatz atomic test fired during testing, the following workflow was executed:

1. **Identify** — Noted the unintended test execution
2. **Query** — Ran the download-cradle and network-connection detections above
3. **Confirm scope** — Both queries returned 0 events, indicating the download failed
4. **Cleanup** — Ran `Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup`
5. **Verify** — Searched for any residual Mimikatz artifacts in Temp directories
6. **Document** — Recorded the exercise for the case file (this document)

This is the same high-level workflow used in real SOC investigations; executing it on a simulated event in a controlled environment builds reflex for the real thing.

---

## Lessons for Production Deployment

1. **Install the Splunk Add-on for Microsoft Sysmon** before relying on field-based detections. Raw XML text search is a fallback, not a production approach.
2. **Audit adversary simulation tests before execution** — `-ShowDetails` on every Atomic test. Numbering is historical, not risk-sorted.
3. **Log command line on Event 4688** — without it, native process auditing is significantly weaker. Registry key `ProcessCreationIncludeCmdLine_Enabled` should be set on every Windows host in scope.
4. **Forward events early** — the SIEM is only as good as its inputs. Verify flow with `stats count by source` before building detection logic on assumptions.
5. **Prepare the IR workflow in advance** — the download-cradle and network-connection queries used during this exercise are reusable across many investigation types. Saving them as named searches or dashboard panels pays off when an incident actually happens.

---

## References

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- [Atomic Red Team T1059.001 atomics](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1059.001)
- [Microsoft — PowerShell -EncodedCommand parameter](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

---

*Case study prepared for the Windows Endpoint Detection Lab project. First validated detection fire; serves as template for future detection case studies.*
