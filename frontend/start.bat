@echo off
cd /d "%~dp0"
if not exist alerts.csv python generate_data.py
python satsa.py >nul && python server.py
