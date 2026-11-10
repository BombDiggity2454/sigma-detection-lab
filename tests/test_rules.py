"""Every rule must: be well-formed, catch its attack samples, stay quiet on
its look-alike benign samples AND on the shared baseline, and ship with a
triage playbook. CI fails if any of that stops being true.
"""

import re
import uuid
from collections import Counter

import pytest

from conftest import FIXTURES_DIR, PLAYBOOKS_DIR, RULES_DIR, read_jsonl
from detlab.engine import load_rules

RULES = load_rules(RULES_DIR)
RULE_IDS = [r.stem for r in RULES]
BASELINE = read_jsonl(FIXTURES_DIR / "_baseline" / "baseline.jsonl")

REQUIRED_FIELDS = ["title", "id", "status", "description", "author", "date",
                   "tags", "logsource", "detection", "falsepositives", "level"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
TACTICS = {"reconnaissance", "resource-development", "initial-access", "execution",
           "persistence", "privilege-escalation", "defense-evasion", "credential-access",
           "discovery", "lateral-movement", "collection", "command-and-control",
           "exfiltration", "impact"}


def test_rules_exist():
    assert RULES, "no rules found under rules/"


def test_rule_ids_are_unique():
    dupes = [i for i, n in Counter(r.id for r in RULES).items() if n > 1]
    assert not dupes, f"duplicate rule ids: {dupes}"


def test_baseline_is_not_empty():
    assert len(BASELINE) >= 10


@pytest.mark.parametrize("rule", RULES, ids=RULE_IDS)
class TestRule:
    def test_metadata(self, rule):
        missing = [f for f in REQUIRED_FIELDS if f not in rule.raw]
        assert not missing, f"missing fields: {missing}"
        uuid.UUID(rule.id)  # raises if not a valid UUID
        assert rule.level in LEVELS
        assert rule.techniques, "needs at least one attack.tXXXX tag"
        tactics = {t.split(".", 1)[1] for t in rule.tags
                   if t.startswith("attack.") and not re.match(r"attack\.t\d", t)}
        assert tactics & TACTICS, "needs at least one ATT&CK tactic tag"

    def test_filename_matches_sigma_convention(self, rule):
        assert re.fullmatch(r"[a-z0-9_]+", rule.stem), "use lowercase_snake_case file names"

    def test_fires_on_every_malicious_sample(self, rule):
        events = read_jsonl(FIXTURES_DIR / rule.stem / "malicious.jsonl")
        assert events, f"add tests/fixtures/{rule.stem}/malicious.jsonl"
        missed = [e.get("_note", e) for e in events if not rule.matches(e)]
        assert not missed, f"rule MISSED (false negatives): {missed}"

    def test_silent_on_benign_lookalikes(self, rule):
        events = read_jsonl(FIXTURES_DIR / rule.stem / "benign.jsonl")
        assert events, f"add tests/fixtures/{rule.stem}/benign.jsonl"
        fps = [e.get("_note", e) for e in events if rule.matches(e)]
        assert not fps, f"rule fired on benign samples (false positives): {fps}"

    def test_silent_on_shared_baseline(self, rule):
        fps = [e.get("_note", e) for e in BASELINE if rule.matches(e)]
        assert not fps, f"rule fired on baseline activity: {fps}"

    def test_has_triage_playbook(self, rule):
        playbook = PLAYBOOKS_DIR / f"{rule.stem}.md"
        assert playbook.exists(), f"add {playbook.relative_to(PLAYBOOKS_DIR.parent)}"
        text = playbook.read_text(encoding="utf-8")
        for heading in ("## Triage steps", "## False positives", "## Escalate if"):
            assert heading in text, f"playbook missing section {heading!r}"
