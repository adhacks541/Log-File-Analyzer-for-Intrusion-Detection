import os
import re
import csv
import logging
from datetime import datetime

# File paths
ssh_log_file = "/var/log/auth.log"
priv_esc_log = os.path.expanduser('~/log-analyzer/data/priv_esc_detection.log')
report_file = os.path.expanduser('~/log-analyzer/data/privilege_escalation_report.csv')

# Ensure directories exist
os.makedirs(os.path.dirname(priv_esc_log), exist_ok=True)
os.makedirs(os.path.dirname(report_file), exist_ok=True)

# Setup logging
logging.basicConfig(filename=priv_esc_log, level=logging.INFO, format='%(asctime)s - %(message)s')

# Patterns for detecting privilege escalation
patterns = [
    re.compile(r'sudo: .* : TTY=.* ; PWD=.* ; USER=root ; COMMAND='),  # Normal sudo usage
    re.compile(r'root.*session opened'),  # Root sessions
    re.compile(r'sudo: pam_unix\(sudo:session\): session opened for user root'),  # PAM root session
]

def detect_privilege_escalation(log_file, report_file):
    """Detect privilege escalation attempts from SSH logs."""
    if not os.path.exists(log_file):
        logging.error(f"SSH log file not found: {log_file}")
        return

    detections = []
    try:
        with open(log_file, "r") as f:
            for line in f:
                for pattern in patterns:
                    if pattern.search(line):
                        timestamp = datetime.now().isoformat()
                        ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                        ip_address = ip_match.group(1) if ip_match else "Unknown"

                        detections.append({
                            "timestamp": timestamp,
                            "ip": ip_address,
                            "description": "Privilege escalation detected",
                            "details": line.strip(),
                        })

                        logging.info(f"Privilege escalation detected: {line.strip()}")

    except Exception as e:
        logging.error(f"Error reading log file: {e}")
        return

    # Save detections to CSV
    if detections:
        try:
            with open(report_file, "w", newline="") as csvfile:
                fieldnames = ["timestamp", "ip", "description", "details"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(detections)

            logging.info(f"Privilege escalation report saved to {report_file}")
            print(f"[+] Privilege escalation attempts detected: {len(detections)}")
        except Exception as e:
            logging.error(f"Error saving report: {e}")
    else:
        logging.info("No privilege escalation attempts detected.")
        print("[*] No privilege escalation attempts detected.")

if __name__ == "__main__":
    detect_privilege_escalation(ssh_log_file, report_file)
