import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RULES_DIR = ROOT / "rules"
FIXTURES_DIR = ROOT / "tests" / "fixtures"
PLAYBOOKS_DIR = ROOT / "playbooks"


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
