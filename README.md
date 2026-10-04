# SAT-SA - Supervisory Analytics Tool for SOC Assessment (prototype)

Fully offline. Requires Python 3 + pandas + numpy. No internet, cloud, SaaS or external AI.

## Run
    pip install pandas numpy
    python generate_data.py     # synthetic SOC data (skip if you have real CSV exports)
    python satsa.py             # analytics -> data.json
    python server.py            # open http://localhost:8000   login: examiner / satsa123

## Screens
Login, Dashboard, Entity drill-down (findings + evidence), Peer benchmarking,
Priority queue, Data & analysis (CSV upload + re-run), Audit trail. "Print" saves a report as PDF.

## Method
Robust peer z-scores (median/MAD), adverse direction only, configurable weights (W in satsa.py).
Rule-based and explainable - no ML model, so no model training/update/hardware needs.
Scores are a prototype methodology, not an official NCIIPC score.

## Air-gapped installation (no internet on the target)
Option A - Python wheels
1. On an internet PC with the same OS and Python version: `sh offline/1_make_bundle_ONLINE_PC.sh` (Windows: the .bat).
2. Copy the whole project folder (with `wheels/`) to the offline machine.
3. There: `sh offline/2_install_OFFLINE_PC.sh` (Windows: the .bat), then `sh start.sh` (Windows: `start.bat`).

Option B - Docker image
1. On an internet PC: `sh offline/docker_build_export_ONLINE_PC.sh` -> creates `satsa_image.tar`.
2. On the offline host: `docker load -i satsa_image.tar` then `docker run --rm -p 127.0.0.1:8000:8000 satsa:1.0`.

Runtime needs only Python 3.10+, pandas and numpy. No internet, cloud, SaaS or external AI at any point.
Hardware: 2 CPU cores, 4 GB RAM is enough for ~1M alerts (measured peak ~0.8 GB).
