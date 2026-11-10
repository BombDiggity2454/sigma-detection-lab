# Playbook: Run Key Persistence Pointing to Suspicious Path or Script Host

| | |
|---|---|
| **Rule** | [`registry_set_win_run_key_suspicious_path.yml`](../rules/windows/registry/registry_set_win_run_key_suspicious_path.yml) |
| **ATT&CK** | [T1547.001 Boot or Logon Autostart: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) |
| **Severity** | Medium (raise to High if the writing process is itself suspicious) |
| **Expected volume** | Low; occasional installer RunOnce entries |

## What this alert means
Something added an entry to a Windows `Run`/`RunOnce` key, so it will start
automatically at logon, and the entry points to a Temp/Public/Downloads folder
or launches PowerShell / mshta / a script host.

## Why it matters
Run keys are the simplest persistence method and are used by most commodity
malware (info-stealers, RATs, loaders). Finding one usually means the
initial payload already executed. The question is what it is and how it got there.

## Triage steps
1. **Read `Details`.** That is the exact command that will run at logon.
2. **Which key?** `HKU\<SID>\…\Run` affects one user; `HKLM\…\Run` affects
   everyone and required admin rights to write.
3. **Who wrote it?** `Image` is the process that set the value. `reg.exe`,
   `powershell.exe`, or the dropped binary itself writing its own Run key
   are all bad signs; a signed installer (`msiexec.exe`) is less so.
4. **Does the referenced file exist?** Hash it and check signature/reputation.
   Find its creation event (Sysmon EID 11) and what downloaded it.
5. **Value name vs. content.** A value named `OneDrive` or `Updater` pointing
   at `Temp\gupdate.exe` is masquerading.

Pivot (Splunk):
```spl
index=windows host="<host>" earliest=-1h latest=+15m
  (EventCode=1 OR EventCode=11 OR EventCode=13)
  (Image="<writer image>" OR TargetFilename="*<file name>" OR TargetObject="*\\CurrentVersion\\Run*")
| table _time EventCode Image CommandLine TargetFilename TargetObject Details
```

## False positives
- Installers that register a one-time `RunOnce` cleanup from Temp.
- Some per-user apps installed to AppData that briefly stage in Temp.

## Escalate if
- The command runs PowerShell / mshta / wscript with inline code.
- The referenced binary is unsigned or unknown, or the writer was `reg.exe`
  launched from a script.
- Value name imitates a known product but points elsewhere.

## Close as benign if
- Writer is a signed installer, the target is that vendor's file, and the
  entry is `RunOnce` (self-deleting). Note the vendor in the ticket.

## Containment (if confirmed)
- Export then delete the registry value; quarantine the referenced file.
- Isolate if the payload has already run (check for network connections).
- Hunt for the same value name / file hash on other hosts.

## Ticket note template
```
Alert: Run key persistence on <host> at <time UTC>
Key: <TargetObject>   Value data: <Details>
Written by: <Image> as <User>
Referenced file: <hash / signer / VT result>
Verdict: <TP / Benign TP / FP>    Action: <escalated / closed / tuning request>
```
