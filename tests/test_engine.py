"""Unit tests for the Sigma evaluator itself.

If the engine is wrong, every rule test is meaningless, so the engine gets
its own tests first.
"""

import pytest

from detlab.engine import Rule, UnsupportedFeature

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def make_rule(detection: dict, logsource: dict | None = None) -> Rule:
    return Rule.from_dict({
        "title": "test",
        "logsource": logsource or {"product": "windows", "category": "process_creation"},
        "detection": detection,
    })


def proc(**fields) -> dict:
    return {"Channel": SYSMON, "EventID": 1, **fields}


# --- value matching -------------------------------------------------------- #

def test_exact_match_is_case_insensitive():
    rule = make_rule({"sel": {"Image": "C:\\Windows\\System32\\cmd.exe"}, "condition": "sel"})
    assert rule.matches(proc(Image="c:\\windows\\system32\\CMD.EXE"))
    assert not rule.matches(proc(Image="C:\\Windows\\System32\\cmd.exe.bak"))


@pytest.mark.parametrize("modifier,value,hit,miss", [
    ("contains", "urlcache", "certutil -URLCACHE -f", "certutil -hashfile"),
    ("startswith", "C:\\Users\\", "C:\\Users\\bob\\a.exe", "D:\\C:\\Users\\a.exe"),
    ("endswith", "\\lsass.exe", "C:\\Windows\\System32\\lsass.exe", "C:\\lsass.exe.txt"),
])
def test_basic_modifiers(modifier, value, hit, miss):
    rule = make_rule({"sel": {f"CommandLine|{modifier}": value}, "condition": "sel"})
    assert rule.matches(proc(CommandLine=hit))
    assert not rule.matches(proc(CommandLine=miss))


def test_value_list_is_or_and_all_modifier_is_and():
    any_rule = make_rule({"sel": {"CommandLine|contains": ["aaa", "bbb"]}, "condition": "sel"})
    all_rule = make_rule({"sel": {"CommandLine|contains|all": ["aaa", "bbb"]}, "condition": "sel"})
    assert any_rule.matches(proc(CommandLine="x aaa x"))
    assert not all_rule.matches(proc(CommandLine="x aaa x"))
    assert all_rule.matches(proc(CommandLine="bbb then aaa"))


def test_wildcards_and_escapes():
    # Sigma: 'C:\\*\evil?.exe' -> literal backslash, then a '*' wildcard.
    rule = make_rule({"sel": {"Image": "C:\\\\*\\evil?.exe"}, "condition": "sel"})
    assert rule.matches(proc(Image="C:\\Temp\\x\\evil1.exe"))
    assert not rule.matches(proc(Image="C:\\Temp\\evil12.exe"))

    # Sigma: '\*' is an escaped, literal star.
    literal = make_rule({"sel": {"CommandLine|contains": "\\*"}, "condition": "sel"})
    assert literal.matches(proc(CommandLine="dir *"))
    assert not literal.matches(proc(CommandLine="dir x"))


def test_trailing_backslash_with_modifier_is_not_an_escape():
    rule = make_rule({"sel": {"Image|startswith": "C:\\Users\\"}, "condition": "sel"})
    assert rule.matches(proc(Image="C:\\Users\\bob\\a.exe"))


def test_regex_is_case_sensitive_unless_i():
    rule = make_rule({"sel": {"CommandLine|re": r"-[Ee]nc\b"}, "condition": "sel"})
    assert rule.matches(proc(CommandLine="powershell -Enc AAA"))
    assert not rule.matches(proc(CommandLine="powershell -ENC AAA"))
    rule_i = make_rule({"sel": {"CommandLine|re|i": r"-enc\b"}, "condition": "sel"})
    assert rule_i.matches(proc(CommandLine="powershell -ENC AAA"))


def test_windash_matches_slash_and_unicode_dashes():
    rule = make_rule({"sel": {"CommandLine|windash|contains": " -enc "}, "condition": "sel"})
    assert rule.matches(proc(CommandLine="powershell /enc AAA"))
    assert rule.matches(proc(CommandLine="powershell \u2013enc AAA"))
    assert not rule.matches(proc(CommandLine="powershell enc AAA"))


def test_cidr():
    rule = make_rule({"sel": {"DestinationIp|cidr": ["10.0.0.0/8"]}, "condition": "sel"},
                     {"product": "windows", "category": "network_connection"})
    net = {"Channel": SYSMON, "EventID": 3}
    assert rule.matches({**net, "DestinationIp": "10.1.2.3"})
    assert not rule.matches({**net, "DestinationIp": "8.8.8.8"})
    assert not rule.matches({**net, "DestinationIp": "not-an-ip"})


def test_null_and_exists():
    null_rule = make_rule({"sel": {"ParentImage": None}, "condition": "sel"})
    assert null_rule.matches(proc(Image="a"))
    assert not null_rule.matches(proc(ParentImage="b"))
    exists_rule = make_rule({"sel": {"ParentImage|exists": True}, "condition": "sel"})
    assert exists_rule.matches(proc(ParentImage="b"))


def test_numeric_field_values():
    rule = make_rule({"sel": {"EventID": 1102}, "condition": "sel"},
                     {"product": "windows", "service": "security"})
    assert rule.matches({"Channel": "Security", "EventID": 1102})
    assert rule.matches({"Channel": "Security", "EventID": "1102"})


def test_keyword_search_ignores_private_fields():
    rule = make_rule({"keywords": ["mimikatz"], "condition": "keywords"})
    assert rule.matches(proc(CommandLine="C:\\tmp\\Mimikatz.exe"))
    assert not rule.matches(proc(_note="mimikatz in a comment only"))


# --- conditions ------------------------------------------------------------ #

DET = {
    "selection_a": {"CommandLine|contains": "aaa"},
    "selection_b": {"CommandLine|contains": "bbb"},
    "filter": {"User|contains": "SYSTEM"},
}


@pytest.mark.parametrize("condition,cmd,user,expected", [
    ("selection_a and not filter", "aaa", "bob", True),
    ("selection_a and not filter", "aaa", "NT AUTHORITY\\SYSTEM", False),
    ("selection_a or selection_b", "bbb", "bob", True),
    ("1 of selection_*", "bbb", "bob", True),
    ("all of selection_*", "bbb", "bob", False),
    ("all of selection_*", "aaa bbb", "bob", True),
    ("(selection_a or selection_b) and not filter", "bbb", "SYSTEM", False),
    ("not selection_a and selection_b", "bbb", "bob", True),
    ("1 of them", "zzz", "SYSTEM", True),
])
def test_conditions(condition, cmd, user, expected):
    rule = make_rule({**DET, "condition": condition})
    assert rule.matches(proc(CommandLine=cmd, User=user)) is expected


def test_list_of_maps_is_or():
    rule = make_rule({"sel": [{"Image|endswith": "\\a.exe"}, {"Image|endswith": "\\b.exe"}],
                      "condition": "sel"})
    assert rule.matches(proc(Image="C:\\b.exe"))
    assert not rule.matches(proc(Image="C:\\c.exe"))


# --- logsource ------------------------------------------------------------- #

def test_logsource_filters_by_channel_and_event_id():
    rule = make_rule({"sel": {"TargetImage|endswith": "\\lsass.exe"}, "condition": "sel"},
                     {"product": "windows", "category": "process_access"})
    event = {"Channel": SYSMON, "EventID": 10, "TargetImage": "C:\\Windows\\System32\\lsass.exe"}
    assert rule.matches(event)
    assert not rule.matches({**event, "EventID": 1})
    assert not rule.matches({**event, "Channel": "Security"})


# --- fail loudly ------------------------------------------------------------- #

@pytest.mark.parametrize("detection", [
    {"sel": {"CommandLine|base64offset|contains": "x"}, "condition": "sel"},
    {"sel": {"a": 1}, "condition": "sel | count() > 5"},
    {"sel": {"a": 1}, "condition": "missing_selection"},
    {"sel": {"a": 1}, "condition": "(sel"},
    {"sel": {"a": 1}},
])
def test_unsupported_syntax_raises(detection):
    with pytest.raises(UnsupportedFeature):
        make_rule(detection)
