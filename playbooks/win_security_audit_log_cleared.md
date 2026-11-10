# Playbook: Security Event Log Cleared

| | |
|---|---|
| **Rule** | [`win_security_audit_log_cleared.yml`](../rules/windows/security/win_security_audit_log_cleared.yml) |
| **ATT&CK** | [T1070.001 Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/) |
| **Severity** | High |
| **Expected volume** | Near zero in production |

## What this alert means
Someone wiped the Windows Security event log on this host. Event 1102 is
written right after the clear and records which account did it.

## Why it matters
There are very few legitimate reasons to clear the Security log on a
production machine. Attackers do it to erase evidence of their logons and
tools, usually near the **end** of their activity on a host. If logs are
forwarded to a SIEM, the copies there survive. Now is the time to read them.

## Triage steps
1. **Who cleared it?** `SubjectUserName` / `SubjectDomainName` and
   `SubjectLogonId`. Is this an admin who would plausibly do this?
2. **Was there a change ticket?** Check with the asset owner / change calendar.
3. **What happened just before?** The SIEM still has the forwarded events.
   Review the hour before the clear on this host: logons (4624), new services
   (7045), process creation, LSASS access, scheduled tasks.
4. **How was it cleared?** Look for `wevtutil cl`, `Clear-EventLog`,
   `Remove-EventLog` or `Get-WinEvent`-based tools in process creation logs.
5. **Other logs too?** System log event 104 on the same host indicates other
   logs (System, PowerShell, Sysmon) were cleared too.
6. **Scope.** Did the same account clear logs on other hosts?

Pivot (Splunk):
```spl
index=windows (EventCode=1102 OR EventCode=104) earliest=-24h
| stats count values(host) as hosts by SubjectUserName
```
```spl
index=windows host="<host>" earliest=-2h latest=+5m
| stats count by EventCode Image TargetUserName
| sort - count
```

## False positives
- Lab, golden-image, or kiosk rebuild processes, which should be documented and
  limited to known hosts.
- Admins troubleshooting a full log without forwarding (bad practice; flag it).

## Escalate if
- No change ticket or owner confirmation.
- The clearing account also shows unusual logons, privilege use, or tooling
  in the forwarded logs.
- More than one host, or more than one log, was cleared.

## Close as benign if
- Confirmed, ticketed maintenance on a non-production host. Still note a
  process improvement (archive instead of clear).

## Containment (if confirmed)
- Treat the host as compromised. Isolate, collect forensic image/triage
  package, disable or reset the clearing account.
- Review GPO so only a restricted group holds the "Manage auditing and
  security log" right.

## Ticket note template
```
Alert: Security log cleared on <host> at <time UTC>
Cleared by: <domain>\<user> (LogonId <id>)
Change ticket: <id or none>
Activity in prior 2h (from SIEM): <summary>
Verdict: <TP / Benign TP / FP>    Action: <escalated / closed>
```
