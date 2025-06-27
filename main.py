import subprocess
import sys
import os
import logging

# Setup logging
LOG_FILE = os.path.expanduser("~/log-analyzer/data/main_pipeline.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Define paths to scripts
SCRIPTS_DIR = os.path.expanduser("~/log-analyzer/scripts")
SCRIPTS_SEQUENCE = [
    "parse_logs.py",                  # Step 1: Parse SSH logs
    "parse_apache_access.py",         # Step 2: Parse Apache logs (moved earlier)
    "detect_intrusions.py",           # Step 3: Detect intrusions (requires both SSH and Apache data)
    "detect_privilege_escalation.py", # Step 4: Detect privilege escalation
    "detect_apache_flood.py",         # Step 5: Detect Apache flood attacks
    "generate_report.py"              # Step 6: Generate final report
]

DASHBOARD_PATH = os.path.expanduser("~/log-analyzer/dashboard/dashboard.py")
LIVE_MONITOR_SCRIPT = os.path.join(SCRIPTS_DIR, "live_monitor.py")

def run_script(script_name):
    """Run a script by name from the scripts directory."""
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(script_path):
        print(f"[!] {script_name} not found in {SCRIPTS_DIR}. Skipping...")
        logging.warning(f"{script_name} not found. Skipping...")
        return False

    print(f"[*] Running {script_name}...")
    logging.info(f"Running {script_name}...")

    try:
        result = subprocess.run(["python3", script_path], check=True)
        print(f"[+] {script_name} completed successfully.")
        logging.info(f"{script_name} completed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] {script_name} failed with return code {e.returncode}.")
        logging.error(f"{script_name} failed with return code {e.returncode}.")
        sys.exit(1)

def start_live_monitoring():
    """Start live monitoring script in the background."""
    if os.path.exists(LIVE_MONITOR_SCRIPT):
        print("[*] Starting live monitoring...")
        logging.info("Starting live monitoring...")
        subprocess.Popen(["python3", LIVE_MONITOR_SCRIPT])
    else:
        print(f"[!] Live monitoring script not found: {LIVE_MONITOR_SCRIPT}")
        logging.warning(f"Live monitoring script not found: {LIVE_MONITOR_SCRIPT}")

def launch_dashboard():
    """Launch the Streamlit dashboard."""
    if os.path.exists(DASHBOARD_PATH):
        print("[*] Launching the dashboard...")
        logging.info("Launching the dashboard...")
        subprocess.run(["streamlit", "run", DASHBOARD_PATH])
    else:
        print(f"[!] Dashboard script not found: {DASHBOARD_PATH}")
        logging.warning(f"Dashboard script not found: {DASHBOARD_PATH}")

def main():
    """Main pipeline for log analysis and intrusion detection."""
    print("[*] Starting log analysis pipeline...")
    logging.info("Starting log analysis pipeline...")

    # Run all scripts in sequence
    for script in SCRIPTS_SEQUENCE:
        run_script(script)

    # Start live monitoring
    start_live_monitoring()

    # Launch the dashboard
    launch_dashboard()

if __name__ == "__main__":
    main()
