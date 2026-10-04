#!/bin/sh
cd "$(dirname "$0")"
[ -f alerts.csv ] || python3 generate_data.py
python3 satsa.py >/dev/null && python3 server.py
