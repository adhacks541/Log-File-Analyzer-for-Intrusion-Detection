#!/bin/bash

echo "[*] Starting virtual environment..."
source venv/bin/activate

echo "[*] Starting Live Monitor..."
python3 scripts/live_monitor.py &

echo "[*] Launching Dashboard..."
echo "[*] All components running. Press Ctrl+C to stop."
streamlit run dashboard/dashboard.py
