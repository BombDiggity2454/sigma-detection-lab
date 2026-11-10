# Playbook: Scheduled Task Created That Runs From a Suspicious Location

| | |
|---|---|
| **Rule** | [`win_security_scheduled_task_suspicious_location.yml`](../rules/windows/security/win_security_scheduled_task_suspicious_location.yml) |
| **ATT&CK** | [T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| **Severity** | High |
| **Expected volume** | Very low; legitimate software rarely schedules tasks from Temp or Public |
| **Prerequisite** | "Audit Other Object Access Events" must be enabled or 4698 is never logged |

## What this alert means
A new scheduled task was registered, and the program it runs lives in a
temporary/shared folder or is a script host (`mshta`, `wscript`, encoded
PowerShell).

## Why it matters
Scheduled tasks are a top persistence technique: the malware survives
reboots and can run as SYSTEM. Attackers often give the task a convincing name
(`GoogleUpdate…`, `Microsoft\Windows\…`) so it blends in.

## Triage steps
1. **Read `TaskContent`.** Find `<Command>` and `<Arguments>`. What runs,
   when (`<Triggers>`), and as whom (`<Principal><UserId>`; `S-1-5-18` = SYSTEM)?
2. **Does the name match the binary?** A task named like a Google/Microsoft
   updater that runs something in `AppData\Local\Temp` is masquerading.
3. **Who created it?** `SubjectUserName`. A regular user creating a task that
   runs as SYSTEM requires admin rights. How did they get them?
4. **Inspect the binary.** Hash it, check signature and VirusTotal. Check
   when it was written (Sysmon EID 11) and by which process.
5. **Remote creation?** Look for a 4624 logon type 3 to this host just before
   the task was created. Tasks created remotely (`schtasks /s`) are a lateral
   movement sign.

Pivot (Splunk):
```spl
index=windows host="<host>" earliest=-1h latest=+1h
  (EventCode=4624 LogonType=3) OR (EventCode=1 Image="*schtasks.exe") OR (EventCode=11 TargetFilename="<binary path>")
| table _time EventCode TargetUserName IpAddress Image CommandLine TargetFilename
```

## False positives
- Badly packaged internal tools that self-install from Temp.
- Some installers that register a one-off post-reboot cleanup task.

## Escalate if
- Binary is unsigned, unknown, or flagged by reputation services.
- Task name imitates a vendor/Microsoft task but the path does not match.
- Action calls `mshta`, `wscript`, `regsvr32`, or encoded PowerShell.
- Task was created via a remote logon, or runs as SYSTEM from a user folder.

## Close as benign if
- The task belongs to a known internal or vendor tool (confirmed with the
  owner) and the binary is signed. Request a tuning filter on
  `TaskName` + creating account, and ask the owner to fix the install path.

## Containment (if confirmed)
- Disable and export the task (`schtasks /query /tn <name> /xml`) for evidence,
  then delete it.
- Quarantine the binary, isolate the host, hunt the hash fleet-wide.

## Ticket note template
```
Alert: Suspicious scheduled task on <host> at <time UTC>
Task: <TaskName>  Runs: <Command> <Arguments>  As: <UserId>  Trigger: <trigger>
Created by: <SubjectDomainName>\<SubjectUserName>  (remote logon: Y/N)
Binary: <hash / signer / VT result>
Verdict: <TP / Benign TP / FP>    Action: <escalated / closed / tuning request>
```
