"""Replay the SigmaHQ (Zircolite) ruleset against every labelled OTRF Windows case.

Writes results/raw/alerts.csv (one row per case x fired rule), cases.json and
run_info.json. Metrics are computed separately by metrics.py.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sqlite3
import sys
import time
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from labels import Attack, load_cases, rule_techniques  # noqa: E402
from replay import Replay, flatten, load_events  # noqa: E402

RULES: list[dict] = []
EVENT_FIELDS = ["Channel", "EventID", "Hostname", "Image", "CommandLine", "ParentImage", "ParentCommandLine",
                "HostApplication", "SourceImage", "TargetImage", "ImageLoaded", "TargetObject",
                "TargetFilename", "PipeName", "SubjectUserName", "TargetUserName", "ProcessName",
                "NewProcessName", "ScriptBlockText", "Payload", "ServiceName", "ServiceFileName"]


def _init(rules_path: str):
    global RULES
    RULES = json.loads(Path(rules_path).read_text())


def run_case(case: dict) -> dict:
    t0 = time.time()
    rows, chans, bad = [], Counter(), 0
    for f in case["files"]:
        events, b = load_events(Path(f))
        bad += b
        for e in events:
            r = flatten(e, Path(f).name)
            rows.append(r)
            chans[str(r.get("Channel", "")).lower()] += 1
    db = Replay(rows)
    # The merged ruleset carries one Sigma rule up to twice (Sysmon and generic
    # Windows mappings) under the same id; a rule's alerts are the union of both.
    matched: dict[str, set] = {}
    errors, evaluated = [], set()
    for rule in RULES:
        if not db.can_match(rule):
            continue
        evaluated.add(rule["id"])
        ids, err = db.run(rule)
        if err:
            errors.append({"rule_id": rule["id"], "title": rule["title"], "error": err})
        if ids:
            matched.setdefault(rule["id"], set()).update(ids)
    hits = [{"rule_id": k, "n_events": len(v)} for k, v in matched.items()]
    evaluated = len(evaluated)
    # Key fields of every matched event, for false-positive attribution (attribution.py)
    cols = [c for c in EVENT_FIELDS if c.lower() in db.columns]
    sel = ", ".join(f'"{c}"' for c in cols)
    ev_rows = []
    for rid, ids in matched.items():
        for row in db.conn.execute(f"SELECT row_id, {sel} FROM logs WHERE row_id IN ({','.join(map(str, sorted(ids)))})"):
            rec = dict(zip(["row_id"] + cols, row))
            ev_rows.append({"rule_id": rid, **{k: (str(v)[:600] if v is not None else "") for k, v in rec.items()}})
    return {"id": case["id"], "n_events": len(rows), "bad_lines": bad, "channels": dict(chans), "hits": hits,
            "events": ev_rows,
            "errors": errors, "rules_evaluated": evaluated, "regex_timeouts": db.regex_timeouts,
            "seconds": round(time.time() - t0, 1)}


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--security-datasets", default="ext/Security-Datasets")
    ap.add_argument("--rules", default="ext/Zircolite/rules/rules_windows_merged.json")
    ap.add_argument("--attack", default="ext/attack-stix-data/enterprise-attack/enterprise-attack.json")
    ap.add_argument("--out", default="results/raw")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--limit", type=int, default=0, help="run only the first N cases (smoke test)")
    a = ap.parse_args()

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    attack = Attack(Path(a.attack))
    cases, notes = load_cases(Path(a.security_datasets), attack)
    if a.limit:
        cases = cases[: a.limit]
    rules = json.loads(Path(a.rules).read_text())
    by_id = {r["id"]: r for r in rules}

    t0 = time.time()
    with Pool(a.workers, initializer=_init, initargs=(a.rules,)) as pool:
        results = []
        for i, res in enumerate(pool.imap_unordered(run_case, cases, chunksize=1), 1):
            results.append(res)
            print(f"[{i}/{len(cases)}] {res['id']}: {res['n_events']} events, "
                  f"{len(res['hits'])} rules fired, {len(res['errors'])} errors, {res['seconds']}s", flush=True)
    results.sort(key=lambda r: r["id"])
    res_by_id = {r["id"]: r for r in results}

    with open(out / "alerts.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "rule_id", "title", "level", "status", "source_dir", "n_events", "techniques"])
        for r in results:
            for h in sorted(r["hits"], key=lambda h: h["rule_id"]):
                rule = by_id[h["rule_id"]]
                w.writerow([r["id"], rule["id"], rule["title"], rule.get("level", ""), rule.get("status", ""),
                            rule["filename"].split("/")[0], h["n_events"],
                            ";".join(sorted(rule_techniques(rule, attack)))])
    with open(out / "alert_events.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["case_id", "rule_id", "row_id"] + EVENT_FIELDS)
        w.writeheader()
        for r in results:
            for ev in sorted(r["events"], key=lambda e: (e["rule_id"], int(e["row_id"]))):
                w.writerow({"case_id": r["id"], **ev})
    for c in cases:
        r = res_by_id[c["id"]]
        c.update(n_events=r["n_events"], channels=r["channels"], rules_evaluated=r["rules_evaluated"],
                 rule_errors=r["errors"], regex_timeouts=r["regex_timeouts"], bad_lines=r["bad_lines"])
    (out / "cases.json").write_text(json.dumps(cases, indent=1))
    (out / "run_info.json").write_text(json.dumps({
        "attack_version": attack.version, "n_rules": len(rules), "rules_sha256": sha256(Path(a.rules)),
        "label_notes": notes, "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
        "wall_seconds": round(time.time() - t0, 1),
    }, indent=1))
    print(f"done: {len(cases)} cases in {time.time() - t0:.0f}s -> {out}")


if __name__ == "__main__":
    main()
