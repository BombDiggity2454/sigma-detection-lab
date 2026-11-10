# Playbook: Suspicious Process Opened LSASS With Memory-Read Access

| | |
|---|---|
| **Rule** | [`proc_access_win_lsass_memory_read.yml`](../rules/windows/process_access/proc_access_win_lsass_memory_read.yml) |
| **ATT&CK** | [T1003.001 OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| **Severity** | High |
| **Expected volume** | Low once EDR/AV agents are filtered by full path |

## What this alert means
A process asked Windows for permission to read the memory of `lsass.exe`, the
process that holds logged-on users' password hashes and Kerberos tickets.

## Why it matters
If an attacker dumps LSASS they can reuse those credentials to move laterally
(pass-the-hash, pass-the-ticket). This usually happens **after** initial
access and privilege escalation, so a true positive means the intrusion is
already well advanced. Treat it as urgent.

## Triage steps
1. **Who opened LSASS?** Look at `SourceImage`. Is it a security product in
   its normal install path, or something in `Temp`, `Public`, `ProgramData`,
   `Downloads`?
2. **Access rights.** `GrantedAccess` `0x1010` is the Mimikatz signature;
   `0x1fffff` (all access) is typical of ProcDump and `comsvcs.dll` MiniDump.
3. **Call trace.** `CallTrace` containing `UNKNOWN(...)` means code running
   from memory that isn't backed by a file on disk, a strong sign of injected
   or reflectively loaded tooling. `dbghelp.dll` / `comsvcs.dll` means a
   dump file is being written.
4. **Look for a dump file.** Sysmon EID 11 (file create) for `*.dmp` on the
   host around the same time.
5. **Process creation.** How did `SourceImage` get there? Find its EID 1
   and parent chain, and any download (certutil, browser, PowerShell).
6. **Masquerading check.** A trusted name (`MsMpEng.exe`, `svchost.exe`) in
   the wrong folder is malicious by definition.

Pivot (Splunk):
```spl
index=windows host="<host>" earliest=-2h latest=+1h
  ((EventCode=11 TargetFilename="*.dmp") OR (EventCode=1 Image="<SourceImage>"))
| table _time EventCode Image CommandLine ParentImage TargetFilename User
```

## False positives
- EDR / AV / vulnerability scanners not yet in the filter list.
- Windows Error Reporting (`WerFault.exe`) if LSASS itself crashed.
- Admins creating a dump for Microsoft support (should have a change ticket).

## Escalate if
- `SourceImage` is unsigned, in a user-writable path, or is a renamed trusted
  binary in the wrong location.
- `rundll32.exe` with `comsvcs.dll` in the command line.
- A `.dmp` file was created, or the dump was copied off the host.
- `CallTrace` contains `UNKNOWN(` frames.

## Close as benign if
- `SourceImage` is a security product at its expected full path, with a
  valid signature, and the vendor documents LSASS access. File a tuning
  request to add it to `filter_main_*` by **full path**, never by name only.

## Containment (if confirmed)
- Isolate the host immediately.
- Assume every account that had an interactive session on the host is
  compromised: reset passwords, and for privileged accounts revoke Kerberos
  tickets (reset `krbtgt` twice if a Domain Admin was exposed, coordinated with IR).
- Hunt for the same `SourceImage` hash across the fleet.

## Ticket note template
```
Alert: LSASS memory access on <host> at <time UTC>
Source: <SourceImage> (signed: Y/N)  GrantedAccess: <value>  CallTrace: <summary>
Dump file: <path or none found>
Accounts exposed: <users logged on to host>
Verdict: <TP / Benign TP / FP>    Action: <escalated / closed / tuning request>
```
