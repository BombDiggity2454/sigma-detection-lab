"""Scan a JSONL file of events with every rule and print the alerts.

    python -m detlab scan events.jsonl
    python -m detlab scan events.jsonl --rules rules/ --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import load_rules, scan


def read_jsonl(path: Path) -> list[dict]:
    events = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                sys.exit(f"{path}:{lineno}: invalid JSON ({exc})")
    return events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detlab", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_scan = sub.add_parser("scan", help="run all rules against a JSONL event file")
    p_scan.add_argument("events", type=Path)
    p_scan.add_argument("--rules", type=Path, default=Path("rules"))
    p_scan.add_argument("--json", action="store_true", help="emit alerts as JSON lines")
    args = parser.parse_args(argv)

    rules = load_rules(args.rules)
    events = read_jsonl(args.events)
    hits = scan(rules, events)  # chronological (file order), like an incident timeline

    if args.json:
        for rule, idx, event in hits:
            print(json.dumps({"rule_id": rule.id, "title": rule.title, "level": rule.level,
                              "techniques": rule.techniques, "event_index": idx,
                              "event": event}))
    else:
        print(f"{len(rules)} rules x {len(events)} events -> {len(hits)} alert(s)\n")
        for rule, idx, event in hits:
            host = event.get("Computer", "?")
            when = str(event.get("UtcTime") or event.get("TimeCreated") or "?")
            when = when.replace("T", " ").rstrip("Z")[:23]
            print(f"{when}  [{rule.level.upper():<6}] {rule.title}")
            print(f"{'':25}host={host}  event=#{idx}  {', '.join(rule.techniques)}")
            print(f"{'':25}playbook: playbooks/{rule.stem}.md\n")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
