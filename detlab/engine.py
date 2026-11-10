"""A small, dependency-light Sigma rule evaluator.

This is NOT a full Sigma implementation. It supports the subset of the
specification that this repository's rules use, and fails loudly on anything
else so a rule can never silently "pass" because a feature was ignored.

Supported:
  * selections as maps (AND across fields) or lists of maps (OR)
  * keyword lists (value searched across every field of the event)
  * value lists (OR), or AND with the ``all`` modifier
  * modifiers: contains, startswith, endswith, all, re (+ i/m/s), windash,
    cidr, exists
  * ``*`` and ``?`` wildcards, with ``\\*`` / ``\\?`` escapes
  * case-insensitive matching (Sigma default; ``re`` is case-sensitive)
  * conditions: and / or / not / parentheses / ``1 of x*`` / ``all of x*`` /
    ``1 of them`` / ``all of them``, and lists of conditions

Not supported (raises ``UnsupportedFeature``): aggregations (``| count()``),
correlation rules, base64/base64offset/utf16 modifiers, field references.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import yaml

from .logsource import logsource_matches

Event = Mapping[str, Any]
Predicate = Callable[[Event], bool]


class UnsupportedFeature(ValueError):
    """Raised when a rule uses Sigma syntax this engine does not implement."""


# --------------------------------------------------------------------------- #
# Value matching
# --------------------------------------------------------------------------- #

_WINDASH_CHARS = ("-", "/", "–", "—", "―")


def _wildcard_to_regex(value: str) -> str:
    """Translate a Sigma string (with * ? and backslash escapes) to a regex."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def _to_str(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


@dataclass
class FieldMatcher:
    """Matches one ``Field|modifiers: values`` entry of a selection."""

    field: str | None  # None == keyword search across all fields
    patterns: list[Callable[[str], bool]] = field(default_factory=list)
    require_all: bool = False
    null_check: bool = False
    exists: bool | None = None

    def __call__(self, event: Event) -> bool:
        if self.exists is not None:
            present = self.field in event and event[self.field] not in (None, "")
            return present == self.exists

        if self.field is None:
            candidates = [_to_str(v) for k, v in event.items() if not k.startswith("_")]
        else:
            raw = event.get(self.field)
            if self.null_check:
                return raw is None or raw == ""
            if raw is None:
                return False
            candidates = [_to_str(v) for v in raw] if isinstance(raw, list) else [_to_str(raw)]

        def hit(pattern: Callable[[str], bool]) -> bool:
            return any(pattern(c) for c in candidates)

        if self.require_all:
            return all(hit(p) for p in self.patterns)
        return any(hit(p) for p in self.patterns)


def _build_field_matcher(spec: str | None, values: Any) -> FieldMatcher:
    name, *mods = spec.split("|") if spec is not None else [None]
    mods = [m.lower() for m in mods]
    matcher = FieldMatcher(field=name)

    if not isinstance(values, list):
        values = [values]

    if "exists" in mods:
        matcher.exists = bool(values[0])
        return matcher

    if values == [None]:
        matcher.null_check = True
        return matcher

    str_values = [_to_str(v) for v in values]

    known = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s",
             "windash", "cidr"}
    unknown = [m for m in mods if m not in known]
    if unknown:
        raise UnsupportedFeature(f"modifier(s) {unknown} on field {name!r}")

    matcher.require_all = "all" in mods

    if "windash" in mods:
        expanded: list[str] = []
        for v in str_values:
            expanded.extend({v.replace("-", d) for d in _WINDASH_CHARS})
        str_values = expanded

    if "cidr" in mods:
        nets = [ipaddress.ip_network(v, strict=False) for v in str_values]

        def make_cidr(net: ipaddress._BaseNetwork) -> Callable[[str], bool]:
            def check(s: str) -> bool:
                try:
                    return ipaddress.ip_address(s) in net
                except ValueError:
                    return False
            return check

        matcher.patterns = [make_cidr(n) for n in nets]
        return matcher

    if "re" in mods:
        flags = 0
        flags |= re.IGNORECASE if "i" in mods else 0
        flags |= re.MULTILINE if "m" in mods else 0
        flags |= re.DOTALL if "s" in mods else 0
        matcher.patterns = [re.compile(v, flags).search for v in str_values]
        return matcher

    # Modifier wildcards are added *after* translating the value, so a value
    # ending in a backslash (e.g. 'C:\Users\') is not misread as '\*' (an
    # escaped literal star) once the wildcard is appended.
    prefix = ".*" if ("contains" in mods or "endswith" in mods or name is None) else ""
    suffix = ".*" if ("contains" in mods or "startswith" in mods or name is None) else ""

    compiled = [
        re.compile(prefix + _wildcard_to_regex(v) + suffix, re.IGNORECASE | re.DOTALL)
        for v in str_values
    ]
    matcher.patterns = [c.fullmatch for c in compiled]
    return matcher


def _build_selection(name: str, body: Any) -> Predicate:
    """A selection is a map (AND), a list of maps (OR), or a keyword list."""
    if isinstance(body, dict):
        parts = [_build_field_matcher(k, v) for k, v in body.items()]
        return lambda e: all(p(e) for p in parts)

    if isinstance(body, list):
        if all(isinstance(item, dict) for item in body):
            maps = [_build_selection(name, item) for item in body]
            return lambda e: any(m(e) for m in maps)
        if all(not isinstance(item, (dict, list)) for item in body):
            kw = _build_field_matcher(None, body)
            return kw

    if isinstance(body, (str, int)):
        return _build_field_matcher(None, [body])

    raise UnsupportedFeature(f"cannot interpret selection {name!r}: {body!r}")


# --------------------------------------------------------------------------- #
# Condition parsing (recursive descent; precedence: not > and > or)
# --------------------------------------------------------------------------- #

_TOKEN_RE = re.compile(
    r"\s*(?:(?P<lp>\()|(?P<rp>\))|(?P<quant>(?:1|all|any)\s+of\s+[\w*]+)"
    r"|(?P<op>and|or|not)\b|(?P<ident>[\w*]+)|(?P<bad>\S+))",
    re.IGNORECASE,
)


class _ConditionParser:
    def __init__(self, text: str, selections: dict[str, Predicate]):
        if "|" in text:
            raise UnsupportedFeature(f"aggregation in condition: {text!r}")
        self.selections = selections
        self.tokens: list[tuple[str, str]] = []
        for m in _TOKEN_RE.finditer(text):
            kind = m.lastgroup
            if kind == "bad":
                raise UnsupportedFeature(f"unexpected token {m.group(kind)!r} in {text!r}")
            if kind:
                self.tokens.append((kind, m.group(kind)))
        self.pos = 0

    def parse(self) -> Predicate:
        expr = self._or()
        if self.pos != len(self.tokens):
            raise UnsupportedFeature(f"trailing tokens in condition: {self.tokens[self.pos:]}")
        return expr

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take_op(self, word: str) -> bool:
        tok = self._peek()
        if tok and tok[0] == "op" and tok[1].lower() == word:
            self.pos += 1
            return True
        return False

    def _or(self) -> Predicate:
        terms = [self._and()]
        while self._take_op("or"):
            terms.append(self._and())
        return terms[0] if len(terms) == 1 else (lambda e, t=terms: any(x(e) for x in t))

    def _and(self) -> Predicate:
        terms = [self._not()]
        while self._take_op("and"):
            terms.append(self._not())
        return terms[0] if len(terms) == 1 else (lambda e, t=terms: all(x(e) for x in t))

    def _not(self) -> Predicate:
        if self._take_op("not"):
            inner = self._not()
            return lambda e: not inner(e)
        return self._atom()

    def _atom(self) -> Predicate:
        tok = self._peek()
        if tok is None:
            raise UnsupportedFeature("condition ended unexpectedly")
        kind, text = tok
        self.pos += 1
        if kind == "lp":
            inner = self._or()
            closing = self._peek()
            if not closing or closing[0] != "rp":
                raise UnsupportedFeature("unbalanced parentheses in condition")
            self.pos += 1
            return inner
        if kind == "quant":
            quant, _, pattern = text.split(None, 2)
            return self._quantifier(quant.lower(), pattern)
        if kind == "ident":
            if text not in self.selections:
                raise UnsupportedFeature(f"condition references unknown selection {text!r}")
            return self.selections[text]
        raise UnsupportedFeature(f"unexpected token {text!r}")

    def _quantifier(self, quant: str, pattern: str) -> Predicate:
        if pattern == "them":
            names = [n for n in self.selections if not n.startswith("_")]
        else:
            names = [n for n in self.selections if fnmatch.fnmatchcase(n, pattern)]
        if not names:
            raise UnsupportedFeature(f"'{quant} of {pattern}' matches no selections")
        preds = [self.selections[n] for n in names]
        if quant == "all":
            return lambda e: all(p(e) for p in preds)
        return lambda e: any(p(e) for p in preds)


# --------------------------------------------------------------------------- #
# Rule
# --------------------------------------------------------------------------- #


@dataclass
class Rule:
    path: Path
    raw: dict[str, Any]
    _predicate: Predicate

    @property
    def id(self) -> str:
        return str(self.raw.get("id", ""))

    @property
    def title(self) -> str:
        return str(self.raw.get("title", ""))

    @property
    def level(self) -> str:
        return str(self.raw.get("level", ""))

    @property
    def tags(self) -> list[str]:
        return list(self.raw.get("tags") or [])

    @property
    def techniques(self) -> list[str]:
        """ATT&CK technique IDs from tags, e.g. 'attack.t1003.001' -> 'T1003.001'."""
        out = []
        for tag in self.tags:
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag, re.IGNORECASE)
            if m:
                out.append(m.group(1).upper())
        return out

    @property
    def logsource(self) -> dict[str, Any]:
        return dict(self.raw.get("logsource") or {})

    @property
    def stem(self) -> str:
        return self.path.stem

    def matches(self, event: Event) -> bool:
        return logsource_matches(self.logsource, event) and self._predicate(event)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], path: Path | str = "<memory>") -> "Rule":
        detection = dict(raw.get("detection") or {})
        condition = detection.pop("condition", None)
        if condition is None:
            raise UnsupportedFeature("rule has no detection.condition")
        if "timeframe" in detection:
            raise UnsupportedFeature("timeframe/aggregation rules are not supported")

        selections = {name: _build_selection(name, body) for name, body in detection.items()}
        conditions = condition if isinstance(condition, list) else [condition]
        preds = [_ConditionParser(str(c), selections).parse() for c in conditions]
        predicate: Predicate = preds[0] if len(preds) == 1 else (lambda e: any(p(e) for p in preds))
        return cls(path=Path(path), raw=raw, _predicate=predicate)

    @classmethod
    def from_file(cls, path: Path | str) -> "Rule":
        path = Path(path)
        with path.open(encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        return cls.from_dict(raw, path)


def load_rules(directory: Path | str) -> list[Rule]:
    """Load every *.yml / *.yaml rule under ``directory`` (recursively)."""
    directory = Path(directory)
    paths = sorted([*directory.rglob("*.yml"), *directory.rglob("*.yaml")])
    return [Rule.from_file(p) for p in paths]


def scan(rules: Iterable[Rule], events: Iterable[Event]) -> list[tuple[Rule, int, Event]]:
    """Return (rule, event_index, event) for every rule hit."""
    rules = list(rules)
    hits = []
    for idx, event in enumerate(events):
        for rule in rules:
            if rule.matches(event):
                hits.append((rule, idx, event))
    return hits
