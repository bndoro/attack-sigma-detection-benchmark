"""Compute RQ1-RQ3 metrics, tables and figures from results/raw/."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))
from labels import Attack, parent, rule_techniques  # noqa: E402

LEVELS = ["informational", "low", "medium", "high", "critical"]
THRESHOLDS = {"all": 0, "medium+": 2, "high+": 3}
BACKGROUND_SHARE = 0.20  # a rule firing off-target in >=20% of cases is lab background


def at_least(level: str, k: int) -> bool:
    return LEVELS.index(level) >= k if level in LEVELS else k == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="results/raw")
    ap.add_argument("--rules", default="ext/Zircolite/rules/rules_windows_merged.json")
    ap.add_argument("--attack", default="ext/attack-stix-data/enterprise-attack/enterprise-attack.json")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    raw, out = Path(a.raw), Path(a.out)
    (out / "tables").mkdir(parents=True, exist_ok=True)
    (out / "figures").mkdir(parents=True, exist_ok=True)

    attack = Attack(Path(a.attack))
    cases = json.loads((raw / "cases.json").read_text())
    alerts = pd.read_csv(raw / "alerts.csv", dtype={"techniques": str}).fillna({"techniques": ""})
    alerts["techs"] = alerts["techniques"].map(lambda s: set(filter(None, s.split(";"))))
    alerts["parents"] = alerts["techs"].map(lambda s: {parent(t) for t in s})
    rules = {r["id"]: r for r in json.loads(Path(a.rules).read_text())}
    labels = {c["id"]: c["labels"] for c in cases}

    # Static content inventory: how many unique rules carry each technique tag
    exact_rules, family_rules = defaultdict(set), defaultdict(set)
    for rid, r in rules.items():
        for t in rule_techniques(r, attack):
            exact_rules[t].add(rid)
            family_rules[parent(t)].add(rid)

    # Mark each alert on-/off-target relative to its case labels
    def on_target(row, mode):
        ls = labels[row.case_id]
        if mode == "exact":
            return bool(row.techs & set(ls))
        return bool(row.parents & {parent(l) for l in ls})
    alerts["on_exact"] = alerts.apply(on_target, axis=1, mode="exact")
    alerts["on_family"] = alerts.apply(on_target, axis=1, mode="family")

    n_cases = len(cases)
    off = alerts[~alerts.on_family]
    bg_share = off.groupby("rule_id").case_id.nunique() / n_cases
    background = set(bg_share[bg_share >= BACKGROUND_SHARE].index)
    alerts["background"] = alerts.rule_id.isin(background)

    # ---------------- RQ1: per (case, label) detection
    pairs = []
    for c in cases:
        ca = alerts[alerts.case_id == c["id"]]
        for l in c["labels"]:
            rec = {"case_id": c["id"], "technique": l, "parent": parent(l),
                   "name": attack.name.get(l, ""), "tactics": ";".join(attack.tactics.get(l, [])),
                   "relabelled": l not in c["raw_labels"]}
            for th, k in THRESHOLDS.items():
                lv = ca.loc[ca.level.map(lambda x: at_least(x, k)).astype(bool)]
                rec[f"exact_{th}"] = bool(lv.techs.map(lambda s: l in s).any())
                rec[f"family_{th}"] = bool(lv.parents.map(lambda s: parent(l) in s).any())
                rec[f"any_{th}"] = len(lv) > 0
            pairs.append(rec)
    pairs = pd.DataFrame(pairs)
    pairs.to_csv(out / "tables" / "case_technique_detection.csv", index=False)

    summary = {"n_cases": n_cases, "n_pairs": len(pairs), "n_techniques": pairs.technique.nunique(),
               "n_parent_techniques": pairs.parent.nunique(), "attack_version": attack.version,
               "n_rules_unique": len(rules), "background_rules": len(background),
               "total_events": int(sum(c["n_events"] for c in cases))}
    for th in THRESHOLDS:
        for mode in ("exact", "family", "any"):
            col = f"{mode}_{th}"
            per_tech = pairs.groupby("technique")[col].mean()
            summary[f"pair_rate_{col}"] = round(pairs[col].mean(), 4)
            summary[f"macro_rate_{col}"] = round(per_tech.mean(), 4)
            summary[f"tech_cov_{col}"] = round((per_tech > 0).mean(), 4)

    # Per-technique table
    tech = pairs.groupby(["technique", "name", "tactics"]).agg(
        cases=("case_id", "count"),
        exact_all=("exact_all", "mean"), family_all=("family_all", "mean"),
        family_medium=("family_medium+", "mean"), family_high=("family_high+", "mean"),
    ).reset_index()
    tech["rules_tagged_exact"] = tech.technique.map(lambda t: len(exact_rules.get(t, ())))
    tech["rules_tagged_family"] = tech.technique.map(lambda t: len(family_rules.get(parent(t), ())))

    # ---------------- RQ2: false-positive cost (bounded)
    fp_rows = []
    for th, k in THRESHOLDS.items():
        lv = alerts.loc[alerts.level.map(lambda x: at_least(x, k)).astype(bool)]
        det = pairs[f"family_{th}"].sum()
        upper_ev = lv[~lv.on_family].n_events.sum()
        lower_ev = lv[(~lv.on_family) & lv.background].n_events.sum()
        upper_hits = (~lv.on_family).sum()
        lower_hits = ((~lv.on_family) & lv.background).sum()
        fp_rows.append({"threshold": th, "true_detections": int(det),
                        "on_target_alerts": int(lv[lv.on_family].n_events.sum()),
                        "fp_alerts_upper": int(upper_ev), "fp_alerts_lower": int(lower_ev),
                        "fp_per_detection_upper": round(upper_ev / det, 2) if det else None,
                        "fp_per_detection_lower": round(lower_ev / det, 2) if det else None,
                        "fp_rulehits_upper": int(upper_hits), "fp_rulehits_lower": int(lower_hits),
                        "fp_rulehits_per_detection_upper": round(upper_hits / det, 2) if det else None,
                        "fp_rulehits_per_detection_lower": round(lower_hits / det, 2) if det else None})
    fp = pd.DataFrame(fp_rows)
    fp.to_csv(out / "tables" / "fp_cost.csv", index=False)

    # Per-technique FP cost (all levels): off-target alerts in that technique's cases / its detections
    tcost = []
    for t, g in pairs.groupby("technique"):
        ids = set(g.case_id)
        ca = alerts[alerts.case_id.isin(ids)]
        det = g.family_all.sum()
        tcost.append({"technique": t,
                      "fp_upper_per_case": ca[~ca.on_family].n_events.sum() / len(ids),
                      "fp_lower_per_case": ca[(~ca.on_family) & ca.background].n_events.sum() / len(ids),
                      "fp_upper_per_detection": (ca[~ca.on_family].n_events.sum() / det) if det else float("nan")})
    tech = tech.merge(pd.DataFrame(tcost), on="technique")
    tech.sort_values(["family_all", "cases"], ascending=[False, False]).to_csv(
        out / "tables" / "per_technique.csv", index=False, float_format="%.3f")

    # Off-target rule inventory (what generates the FP load)
    offr = off.groupby(["rule_id", "title", "level"]).agg(
        cases=("case_id", "nunique"), events=("n_events", "sum")).reset_index()
    offr["background"] = offr.rule_id.isin(background)
    offr["techniques"] = offr.rule_id.map(lambda r: ";".join(sorted(rule_techniques(rules[r], attack))))
    offr.sort_values(["cases", "events"], ascending=False).to_csv(
        out / "tables" / "off_target_rules.csv", index=False)

    # ---------------- RQ3: tactic coverage (ATT&CK v19 tactics of each label)
    trows = []
    for tac in attack.tactic_order:
        sub = pairs[pairs.tactics.str.split(";").map(lambda s: tac in s)]
        if sub.empty:
            continue
        trows.append({"tactic": tac, "pairs": len(sub), "techniques": sub.technique.nunique(),
                      "family_all": sub.family_all.mean(), "family_high": sub["family_high+"].mean(),
                      "exact_all": sub.exact_all.mean()})
    tactics = pd.DataFrame(trows)
    tactics.to_csv(out / "tables" / "tactic_coverage.csv", index=False, float_format="%.3f")

    never = tech[tech.family_all == 0]
    summary["never_detected"] = never.technique.tolist()
    summary["never_detected_no_rule"] = never[never.rules_tagged_family == 0].technique.tolist()
    summary["relabelled_pairs"] = int(pairs.relabelled.sum())
    (out / "summary.json").write_text(json.dumps(summary, indent=1))

    # ---------------- figures
    plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False})
    t2 = tech.sort_values(["family_all", "technique"])
    fig, ax = plt.subplots(figsize=(7, 9))
    y = range(len(t2))
    ax.barh(y, t2.family_all, color="#9db4d6", label="any level")
    ax.barh(y, t2.family_high, color="#2f5d9a", height=0.45, label="high/critical only")
    ax.set_yticks(list(y), [f"{r.technique} ({r.cases})" for r in t2.itertuples()], fontsize=7)
    ax.set_xlabel("Detection rate (family match), share of cases")
    ax.set_title("Fig. 1. Per-technique detection rate of SigmaHQ rules")
    ax.legend(loc="lower right", frameon=False)
    fig.tight_layout(); fig.savefig(out / "figures" / "fig1_per_technique.png", dpi=200); plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 3.2))
    x = range(len(tactics))
    ax.bar([i - 0.2 for i in x], tactics.family_all, 0.4, color="#9db4d6", label="any level")
    ax.bar([i + 0.2 for i in x], tactics.family_high, 0.4, color="#2f5d9a", label="high/critical only")
    ax.set_xticks(list(x), [f"{t}\n(n={n})" for t, n in zip(tactics.tactic, tactics.pairs)], fontsize=7, rotation=30, ha="right")
    ax.set_ylabel("Detection rate"); ax.set_ylim(0, 1)
    ax.set_title("Fig. 2. Detection rate by ATT&CK v19 tactic")
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout(); fig.savefig(out / "figures" / "fig2_tactics.png", dpi=200); plt.close(fig)

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.scatter(tech.fp_upper_per_case.clip(lower=0.5), tech.family_all, s=12 + 10 * tech.cases, color="#2f5d9a", alpha=0.6)
    for r in tech.itertuples():
        if r.family_all == 0 or r.fp_upper_per_case > tech.fp_upper_per_case.quantile(0.85):
            ax.annotate(r.technique, (max(r.fp_upper_per_case, 0.5), r.family_all), fontsize=6, xytext=(3, 2), textcoords="offset points")
    ax.set_xscale("log"); ax.set_xlabel("Off-target alerts per case (upper-bound FP load, log)")
    ax.set_ylabel("Detection rate (family)")
    ax.set_title("Fig. 3. Coverage vs. alert cost per technique")
    fig.tight_layout(); fig.savefig(out / "figures" / "fig3_coverage_vs_cost.png", dpi=200); plt.close(fig)

    print(json.dumps(summary, indent=1))
    print(fp.to_string(index=False))
    print(tactics.to_string(index=False))


if __name__ == "__main__":
    main()
