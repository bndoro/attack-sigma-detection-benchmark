"""Ground truth: OTRF metadata -> cases with ATT&CK v19-normalised technique labels."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


class Attack:
    """ATT&CK Enterprise STIX bundle: revoked-by map, tactics, names."""

    def __init__(self, stix_path: Path):
        objs = json.loads(Path(stix_path).read_text())["objects"]
        self.version = next(o for o in objs if o["type"] == "x-mitre-collection").get("x_mitre_version")
        aps = {o["id"]: o for o in objs if o["type"] == "attack-pattern"}

        def ext(o):
            return next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-attack")

        revoked_by = {r["source_ref"]: r["target_ref"] for r in objs
                      if r["type"] == "relationship" and r["relationship_type"] == "revoked-by"}
        self.redirect: dict[str, str] = {}
        self.name: dict[str, str] = {}
        self.tactics: dict[str, list[str]] = {}
        for sid, o in aps.items():
            tid = ext(o)
            if o.get("revoked") and sid in revoked_by and revoked_by[sid] in aps:
                self.redirect[tid] = ext(aps[revoked_by[sid]])
            elif not o.get("revoked") and not o.get("x_mitre_deprecated"):
                self.name[tid] = o["name"]
                self.tactics[tid] = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                     if p.get("kill_chain_name") == "mitre-attack"]
        self.tactic_order = []
        matrix = next(o for o in objs if o["type"] == "x-mitre-matrix" and not o.get("revoked"))
        tac = {o["id"]: o["x_mitre_shortname"] for o in objs if o["type"] == "x-mitre-tactic"}
        self.tactic_order = [tac[t] for t in matrix["tactic_refs"] if t in tac]

    def norm(self, tid: str) -> str:
        tid = tid.upper()
        seen = set()
        while tid in self.redirect and tid not in seen:
            seen.add(tid)
            tid = self.redirect[tid]
        return tid


def parent(tid: str) -> str:
    return tid.split(".")[0]


def rule_techniques(rule: dict, attack: Attack) -> set[str]:
    out = set()
    for t in rule.get("tags") or []:
        t = t.lower()
        if t.startswith("attack.t") and t[8:9].isdigit():
            out.add(attack.norm(t[len("attack."):].upper()))
    return out


# Metadata links that no longer match a file name in the repository. Each fix is
# a file whose title/description is the same simulation as the metadata entry.
LINK_FIXES = {
    # "Dumping NTDS.dit from Volume Shadow Copy" (2023, Atomic tests 1-2 of T1003.003)
    "datasets/atomic/windows/credential_access/host/cmd_copy_ntds_from_volume_shadow_copy.zip":
        "datasets/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_volume_shadow_copy.zip",
}


def load_cases(sd_root: Path, attack: Attack) -> tuple[list[dict], dict]:
    """One case per Windows metadata entry whose host files are all present."""
    meta_dir = sd_root / "datasets" / "atomic" / "_metadata"
    cases, notes = [], {"missing_files": [], "unlabelled": [], "raw_labels": {}}
    referenced = set()
    for f in sorted(meta_dir.glob("SDWIN-*.yaml")):
        m = yaml.safe_load(f.read_text())
        hosts = [x["link"].split("/master/", 1)[1] for x in (m.get("files") or []) if x.get("type") == "Host"]
        hosts = [LINK_FIXES.get(h, h) for h in hosts]
        referenced.update(hosts)
        paths = [sd_root / h for h in hosts]
        if not paths or not all(p.exists() for p in paths):
            notes["missing_files"].append(m["id"])
            continue
        if any(p.name.endswith(".tar.gz") for p in paths):
            # 2019 Winlogbeat 6.7 exports: fields nest under log_name/event_id/
            # event_data instead of Channel/EventID, and both archives are
            # truncated (gzip: unexpected end of file), so no rule can evaluate.
            notes.setdefault("excluded_format", []).append(m["id"])
            continue
        raw, labels = [], set()
        for a in m.get("attack_mappings") or []:
            t = str(a["technique"]).upper()
            if a.get("sub-technique"):
                t += "." + str(a["sub-technique"]).zfill(3)
            raw.append(t)
            n = attack.norm(t)
            if n in attack.name:  # drops placeholders such as T0000
                labels.add(n)
        notes["raw_labels"][m["id"]] = raw
        if not labels:
            notes["unlabelled"].append(m["id"])
            continue
        cases.append({"id": m["id"], "title": m.get("title", ""), "files": [str(p) for p in paths],
                      "labels": sorted(labels), "raw_labels": raw,
                      "simulation_tools": [t.get("name") for t in (m.get("simulation") or {}).get("tools") or []]})
    on_disk = {str(p.relative_to(sd_root)) for p in (sd_root / "datasets/atomic/windows").glob("*/host/*")
               if p.name.endswith((".zip", ".tar.gz"))}
    notes["unreferenced_files"] = sorted(on_disk - referenced)
    return cases, notes
