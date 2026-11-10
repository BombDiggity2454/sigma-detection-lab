# Playbook: PowerShell Launched With Encoded Command

| | |
|---|---|
| **Rule** | [`proc_creation_win_powershell_encoded_command.yml`](../rules/windows/process_creation/proc_creation_win_powershell_encoded_command.yml) |
| **ATT&CK** | [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/), [T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) |
| **Severity** | High |
| **Expected volume** | Low on workstations; higher on servers managed by RMM/SCCM until those are baselined |

## What this alert means
PowerShell was started with its command hidden inside a base64 string
(`-enc`, `-e`, `-EncodedCommand`, …). You cannot see what it did until you
decode it.

## Why it matters
Encoded PowerShell is one of the most common first steps after a phishing
click: a macro or LNK file launches a hidden PowerShell "download cradle" that
pulls the next stage from the internet. It is also used later for in-memory
tooling (e.g. loading Mimikatz without touching disk).

## Triage steps
1. **Decode the command.** The payload is UTF-16LE base64.
   ```powershell
   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<blob>'))
   ```
   or in CyberChef: *From Base64 → Decode text (UTF-16LE)*. Look for URLs, IPs,
   `IEX`, `DownloadString`, `Invoke-WebRequest`, `FromBase64String` (nested
   encoding), `-w hidden`, AMSI bypass strings.
2. **Check the parent process.** `WINWORD.EXE`, `EXCEL.EXE`, `OUTLOOK.EXE`,
   `mshta.exe`, `wscript.exe` or `WmiPrvSE.exe` as parent is highly suspicious.
   `ccmexec.exe` (SCCM) or a known RMM agent is likely benign.
3. **Was it renamed?** If `Image` is not `powershell.exe`/`pwsh.exe` but
   `OriginalFileName` is, someone copied PowerShell to a new name. Escalate.
4. **Network follow-up.** Any Sysmon EID 3 / proxy / DNS from this host to the
   decoded URL or IP within a few minutes?
5. **Script block logs.** If enabled, EID 4104 on the host shows the
   *decoded and de-obfuscated* script.
6. **Intel.** Run any decoded domains / IPs / hashes through VirusTotal,
   AbuseIPDB, URLhaus.

Pivot (Splunk):
```spl
index=windows host="<host>" earliest=-15m latest=+30m
  (EventCode=1 OR EventCode=3 OR EventCode=11 OR EventCode=4104)
| table _time EventCode Image CommandLine ParentImage DestinationIp TargetFilename ScriptBlockText
```

## False positives
- SCCM / Intune / RMM agents (`ccmexec.exe`, `AgentExecutor.exe`, etc.) that
  wrap scripts in `-EncodedCommand` to avoid quoting issues.
- Some backup and monitoring agents.
Recognize these by a **consistent parent process and signer** and a decoded
script that is clearly administrative.

## Escalate if
- Decoded content downloads or executes anything from the internet.
- Parent is an Office app, script host, browser, or `WmiPrvSE.exe` (remote WMI).
- PowerShell binary was renamed or run from a user-writable path.
- Decoded script disables Defender / AMSI or contains another encoded layer.

## Close as benign if
- Parent is a known, signed management agent **and** the decoded script
  matches that tool's normal behaviour. File a tuning request so the rule
  filters that parent by full path.

## Containment (if confirmed)
- Isolate the host via EDR. Block decoded URLs/IPs at proxy and firewall.
- Pull the originating email/document if a macro was the parent; search for
  other recipients.
- Reset the user's password if any credential-access activity follows.

## Ticket note template
```
Alert: PowerShell Launched With Encoded Command on <host> at <time UTC>
User: <user>   Parent: <parent image>
Decoded: <one-line summary of the decoded script>
Indicators: <URLs / IPs / hashes>
Verdict: <TP / Benign TP / FP>    Action: <escalated / closed / tuning request>
```
