"""Show the events a rule matched in a case, for manual false-positive auditing.

Usage:
  python src/inspect_alerts.py --rule <rule_id> --case <SDWIN-id> [--limit 5]
  python src/inspect_alerts.py --audit-top 15     # writes results/tables/fp_audit_sample.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from replay import Replay, flatten, load_events  # noqa: E402

FIELDS = ["Channel", "EventID", "Hostname", "Image", "CommandLine", "ParentImage", "HostApplication",
          "TargetImage", "SourceImage", "ImageLoaded", "TargetObject", "TargetFilename", "PipeName",
          "SubjectUserName", "TargetUserName", "ScriptBlockText", "Payload"]


def matches(case: dict, rules: list[dict], limit: int):
    rows = []
    for f in case["files"]:
        events, _ = load_events(Path(f))
        rows += [flatten(e, Path(f).name) for e in events]
    db = Replay(rows)
    ids = set()
    for r in rules:
        got, _ = db.run(r)
        ids.update(got)
    cols = [c for c in FIELDS if c.lower() in db.columns]
    q = f'SELECT {", ".join(chr(34)+c+chr(34) for c in cols)} FROM logs WHERE row_id IN ({",".join(map(str, sorted(ids)[:limit]))})'
    return [dict(zip(cols, r)) for r in db.conn.execute(q)] if ids else []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="results/raw")
    ap.add_argument("--rules", default="ext/Zircolite/rules/rules_windows_merged.json")
    ap.add_argument("--rule"); ap.add_argument("--case")
    ap.add_argument("--limit", type=int, default=3)
    ap.add_argument("--audit-top", type=int, default=0)
    a = ap.parse_args()
    rules = json.loads(Path(a.rules).read_text())
    cases = {c["id"]: c for c in json.loads((Path(a.raw) / "cases.json").read_text())}

    if a.audit_top:
        import pandas as pd
        off = pd.read_csv("results/tables/off_target_rules.csv")
        off = off[off.level.isin(["medium", "high", "critical"])].sort_values("events", ascending=False).head(a.audit_top)
        alerts = pd.read_csv(Path(a.raw) / "alerts.csv")
        out = []
        for r in off.itertuples():
            cids = alerts[alerts.rule_id == r.rule_id].case_id.tolist()
            for cid in cids[:2]:  # two example cases per rule
                for ev in matches(cases[cid], [x for x in rules if x["id"] == r.rule_id], 1):
                    out.append({"rule_id": r.rule_id, "title": r.title, "level": r.level, "case_id": cid,
                                "case_title": cases[cid]["title"],
                                **{k: str(v)[:240] for k, v in ev.items() if v not in (None, "")}})
        keys = ["rule_id", "title", "level", "case_id", "case_title"] + FIELDS
        with open("results/tables/fp_audit_sample.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
            w.writeheader(); w.writerows(out)
        print(f"wrote {len(out)} sample events")
        return

    for ev in matches(cases[a.case], [x for x in rules if x["id"] == a.rule], a.limit):
        print(json.dumps({k: v for k, v in ev.items() if v not in (None, "")}, indent=1)[:2000])


if __name__ == "__main__":
    main()
