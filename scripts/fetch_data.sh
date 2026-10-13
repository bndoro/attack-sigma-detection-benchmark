#!/usr/bin/env bash
# Download the pinned inputs into ext/ (about 130 MB).
set -euo pipefail
mkdir -p ext && cd ext
git clone --filter=blob:none --sparse https://github.com/OTRF/Security-Datasets
(cd Security-Datasets && git checkout -q d9d40ef123d2c87d5d3df28c96bcab4f0faccc87 && git sparse-checkout set datasets/atomic/_metadata datasets/atomic/windows)
git clone https://github.com/wagga40/Zircolite
(cd Zircolite && git checkout -q 2557ed1672e9f0281fcb2937bf38dd49cbc52d8e)
git clone --filter=blob:none --sparse https://github.com/mitre-attack/attack-stix-data
(cd attack-stix-data && git checkout -q 6cda5ad8462c79e14fbb872f4e09059b18e0cfc4 && git sparse-checkout set --no-cone /enterprise-attack/enterprise-attack.json)
echo "Inputs ready in ext/"
