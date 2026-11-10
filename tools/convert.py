"""Convert every Sigma rule into SIEM queries with the reference pySigma backends.

    python tools/convert.py           # writes queries/splunk/*.spl and queries/elastic/*.lucene
    python tools/convert.py --check   # fail if the committed queries are out of date

Doubles as validation: if pySigma (the reference Sigma implementation) cannot
parse or convert a rule, this script exits non-zero and CI fails.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# pySigma uses libyaml's CSafeLoader. On very new Python versions PyYAML may be
# installed without the C extension; fall back to the pure-Python loader.
if not hasattr(yaml, "CSafeLoader"):
    yaml.CSafeLoader = yaml.SafeLoader  # type: ignore[attr-defined]

from sigma.backends.elasticsearch import LuceneBackend  # noqa: E402
from sigma.backends.splunk import SplunkBackend  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.pipelines.elasticsearch.windows import ecs_windows  # noqa: E402
from sigma.pipelines.splunk import splunk_windows_pipeline  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
OUT = ROOT / "queries"

TARGETS = {
    "splunk": (lambda: SplunkBackend(splunk_windows_pipeline()), "spl"),
    "elastic": (lambda: LuceneBackend(ecs_windows()), "lucene"),
}


def render() -> dict[Path, str]:
    files: dict[Path, str] = {}
    backends = {name: (factory(), ext) for name, (factory, ext) in TARGETS.items()}
    for rule_path in sorted(RULES.rglob("*.yml")):
        collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
        for name, (backend, ext) in backends.items():
            queries = backend.convert(collection)
            body = "\n".join(str(q) for q in queries)
            header = f"// {collection.rules[0].title}\n// source: {rule_path.relative_to(ROOT).as_posix()}\n"
            files[OUT / name / f"{rule_path.stem}.{ext}"] = header + body + "\n"
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    files = render()
    if args.check:
        stale = [p for p, text in files.items()
                 if not p.exists() or p.read_text(encoding="utf-8") != text]
        if stale:
            print("Out-of-date queries (run: python tools/convert.py):")
            for p in stale:
                print("  ", p.relative_to(ROOT))
            return 1
        print(f"{len(files)} queries up to date")
        return 0

    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(files)} queries to {OUT.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
