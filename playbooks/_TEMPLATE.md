# Playbook: <Rule title>

| | |
|---|---|
| **Rule** | [`rules/.../<rule_file>.yml`](../rules/) |
| **ATT&CK** | [Txxxx.xxx – Name](https://attack.mitre.org/techniques/Txxxx/xxx/) |
| **Severity** | high / medium / low |
| **Expected volume** | e.g. "< 1 per week across the fleet after tuning" |

## What this alert means
One or two plain-English sentences a Tier 1 analyst can read at 3 a.m.

## Why it matters
What the attacker gets if this is real, and where it usually sits in an
intrusion (what came before, what comes next).

## Triage steps
1. **First check.** What to look at in the alert itself.
2. **Context.** Who is the user, what is the host's role?
3. **Process tree.** Parent / grandparent / children.
4. **Pivot.** Related activity on the same host or by the same user within ±1h.
5. **Intel.** Hashes, domains, IPs → reputation lookups.

Example pivot query (Splunk):
```spl
index=windows host=<host> earliest=-1h latest=+1h
| table _time EventCode Image CommandLine ParentImage User
```

## False positives
- Known benign sources and how to recognize them.

## Escalate if
- Concrete, checkable conditions that make this a confirmed or likely incident.

## Close as benign if
- Concrete conditions that make this safe to close, and what to write.

## Containment (if confirmed)
- Isolate host / disable account / block indicator. Who to notify.

## Ticket note template
```
Alert: <title> on <host> at <time UTC>
User: <user>   Process: <image> (parent: <parent>)
Findings: <what you checked and what you saw>
Verdict: True positive / Benign true positive / False positive
Action: <escalated to IR | closed | tuning request filed>
```
