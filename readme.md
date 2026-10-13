# Sigma-vs-ATT&CK Detection Benchmark

CS 530 – Assignment 2 · Blessing Ndoro

This project replays SigmaHQ detection rules against the ATT&CK-labelled Windows atomic datasets in OTRF Security-Datasets. It reports:

- **RQ1:** the detection rate for each technique.
- **RQ2:** a bounded false-positive cost.
- **RQ3:** coverage across tactics, and which techniques are missed.

## Repository layout

| Path | What it does |
|---|---|
| `scripts/fetch_data.sh` | Downloads the pinned datasets, rules and ATT&CK bundle into `ext/` |
| `src/replay.py` | Replay engine: flattens events into SQLite and runs Zircolite's pySigma SQL rules |
| `src/labels.py` | Builds ground truth from OTRF metadata and normalizes labels and rule tags to ATT&CK v19.2 |
| `src/benchmark.py` | Runs every rule against every case and writes `results/raw/` |
| `src/metrics.py` | Computes RQ1–RQ3 and writes `results/tables/`, `results/figures/` and `results/summary.json` |
| `src/inspect_alerts.py` | Shows the events a rule matched in a case, for auditing alerts |
| `results/` | The outputs reported in the paper |

## Pinned inputs

| Input | Repository | Commit |
|---|---|---|
| Telemetry | [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) | `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` |
| Rules: `rules/rules_windows_merged.json` (2,833 unique SigmaHQ rules, SigmaHQ rev `8a481340`, pySigma 2.0.0) | [wagga40/Zircolite](https://github.com/wagga40/Zircolite) | `2557ed1672e9f0281fcb2937bf38dd49cbc52d8e` |
| ATT&CK Enterprise v19.2 STIX | [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) | `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4` |

## Reproduce

You need Python 3.11 or newer and git.

```bash
git clone <this repo> && cd <this repo>
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
bash scripts/fetch_data.sh        # ~130 MB into ext/
python src/benchmark.py           # replay; ~3-4 min on 2 cores
python src/metrics.py             # tables, figures, summary
```

On Windows, run `fetch_data.sh` from Git Bash.

## Expected output

### Console output

The last line of `benchmark.py` reads `done: 97 cases in ...s -> results/raw`.

### `results/summary.json`

| Field | Value |
|---|---|
| `n_cases` | 97 |
| `n_pairs` (case–technique pairs) | 101 |
| `n_techniques` | 55 |
| `total_events` | 768,555 |
| `pair_rate_exact_all` | 0.6436 |
| `pair_rate_family_all` | 0.7525 |
| `tech_cov_family_all` | 0.8545 |
| `tech_cov_family_high+` | 0.6364 |

`never_detected` lists eight techniques: T1012, T1049, T1056.002, T1059.001, T1110.003, T1135, T1210 and T1222.001.

### `results/tables/fp_cost.csv`

| Rule level | Off-target alerts per true detection (upper bound) |
|---|---|
| All levels | 104.59 |
| Medium and above | 63.66 |
| High and above | 17.80 |

Figures 1–3 are written to `results/figures/`.

## Metric definitions

### Case
A case is one OTRF metadata entry. Its labels are its `attack_mappings`, normalized through ATT&CK v19.2 revoked-by relationships:
- T1562.002 becomes T1685.001.
- T1562.004 becomes T1686.

### Detection
- **Exact detection:** a fired rule carries the label's exact technique ID.
- **Family detection:** a fired rule shares the label's parent technique.

Both are reported for three rule-level thresholds: all levels, medium and above, and high and above.

### False-positive cost (bounded)
- **Upper bound:** off-target alerts (rules matching none of the case's labels) per true detection.
- **Lower bound:** only alerts from background rules. A background rule is one that fires off-target in at least 20% of cases.

## Engine note and cross-check

The study used `src/replay.py` because Zircolite's dependencies could not be installed in the build environment. It reproduces Zircolite's evaluation semantics:
- leaf-key flattening;
- `COLLATE NOCASE` columns;
- NULL columns for fields a rule needs but the data lacks;
- `Hashes` splitting;
- a regexp function that treats a value as a non-match after 1 s.

To compare against real Zircolite on one case:

```bash
pip install -e ext/Zircolite
unzip -o ext/Security-Datasets/datasets/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil.zip -d /tmp/case
python ext/Zircolite/zircolite.py -e /tmp/case -j -r ext/Zircolite/rules/rules_windows_merged.json -o /tmp/zircolite_out.json
```

Compare the rule titles in the output with that case's rows in `results/raw/alerts.csv`.

## Exclusions

These are also recorded in `results/raw/run_info.json`.

| Case | Reason |
|---|---|
| SDWIN-230718150800 | Its metadata link was renamed upstream. A fix in `labels.py` maps it to the matching file. |
| SDWIN-190518201922, SDWIN-190518203650 | Winlogbeat 6.7 `.tar.gz` exports. Their fields don't match the schema the rules expect (no `Channel`/`EventID`), and the archives are truncated. Excluded. |
| SDWIN-210427020247 | Its only label is the placeholder T0000. Excluded. |
| Eleven host files | No metadata entry, so no ground truth. Excluded. |

## Licences

Code is MIT. Inputs keep their own licences:
- OTRF Security-Datasets: MIT.
- SigmaHQ rules: DRL 1.1.
- Zircolite: LGPL-3.0.
- MITRE ATT&CK: © The MITRE Corporation, used under its terms of use.
