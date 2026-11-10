# Playbook: Certutil Used to Download a File

| | |
|---|---|
| **Rule** | [`proc_creation_win_certutil_download.yml`](../rules/windows/process_creation/proc_creation_win_certutil_download.yml) |
| **ATT&CK** | [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/), [T1218 System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/) |
| **Severity** | High |
| **Expected volume** | Very low |

## What this alert means
`certutil.exe`, a built-in Windows certificate tool, was told to fetch
something from a URL. That's a known "living off the land" trick for
downloading malware with a trusted Microsoft binary.

## Why it matters
This is usually the step where the attacker brings in their real tools
(credential dumpers, RATs, ransomware). The URL in the command line is a
high-value indicator you can block and hunt for immediately.

## Triage steps
1. **Extract the URL and output path** from `CommandLine`.
2. **Check the URL/IP/domain** reputation (VirusTotal, URLhaus, AbuseIPDB).
   Is it internal PKI (`crl.corp.local`), or an external IP / fresh domain?
3. **Parent process.** `cmd.exe` or `powershell.exe` spawned by Office,
   a script host, or a web server process (`w3wp.exe`) is very bad.
4. **Was it renamed?** `Image` not ending in `certutil.exe` but
   `OriginalFileName` = `CertUtil.exe` means deliberate evasion.
5. **What happened to the file?** Sysmon EID 11 for the output path, then
   EID 1 for that file being executed.
6. **Scope.** Search proxy/DNS logs for the same URL across all hosts.

Pivot (Splunk):
```spl
index=windows host="<host>" earliest=-30m latest=+1h
  ((EventCode=11 TargetFilename="<output path>") OR (EventCode=1 Image="<output path>") OR EventCode=3)
| table _time EventCode Image CommandLine TargetFilename DestinationIp DestinationPort
```
```spl
index=proxy url="*<domain or IP>*" earliest=-7d | stats count by src_ip user url
```

## False positives
- PKI admins testing CRL/AIA reachability with `-urlcache` against
  **internal** certificate servers.

## Escalate if
- URL is external, a raw IP, or has poor reputation.
- A file was written and then executed.
- Parent chain includes Office, a script host, or a web server.
- Certutil was renamed or copied.

## Close as benign if
- URL is an internal PKI endpoint, the user is a PKI/infra admin, and no
  file was executed. Note who confirmed it.

## Containment (if confirmed)
- Block the URL/domain/IP at proxy and firewall; quarantine the downloaded
  file and hunt its hash.
- Isolate the host if the file executed.
- Consider an application-control rule restricting certutil network use.

## Ticket note template
```
Alert: Certutil download on <host> at <time UTC>
User: <user>   Parent: <parent>
URL: <url>  -> <output path>   Reputation: <result>
File executed: Y/N   Hash: <sha256>
Verdict: <TP / Benign TP / FP>    Action: <escalated / closed / tuning request>
```
