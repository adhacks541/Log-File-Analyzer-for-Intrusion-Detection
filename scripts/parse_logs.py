import os
import re
import pandas as pd
from map_to_cve import get_cve_details
import logging

# Setup logging
logging.basicConfig(
    filename=os.path.expanduser('~/log-analyzer/data/parse_logs.log'),
    level=logging.DEBUG,  # Set to DEBUG for detailed insights
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# File paths
ssh_log_file = "/var/log/auth.log"
parsed_logs_file = os.path.expanduser('~/log-analyzer/data/parsed_logs.csv')

# Ensure output directory exists
os.makedirs(os.path.dirname(parsed_logs_file), exist_ok=True)

# Regex pattern for SSH log entries
ssh_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+\d{2}:\d{2}).*Failed password for (?P<user>[^\s]+) from (?P<ip>[^\s]+) port \d+ ssh2"
)

def parse_ssh_logs(log_path, output_path):
    """Parse SSH logs for suspicious activities."""
    if not os.path.exists(log_path):
        logging.error(f"SSH log file not found: {log_path}")
        return 1

    parsed_data = []
    skipped_lines = 0

    logging.info(f"Starting to parse SSH logs from: {log_path}")

    try:
        with open(log_path, "r") as log_file:
            for line in log_file:
                match = ssh_pattern.search(line)
                if match:
                    event = "Failed SSH Login"
                    try:
                        # Map CVE dynamically with fallback to static mapping
                        cve_id, cve_description, cvss_score, exploitability = get_cve_details("SSH")
                    except Exception as e:
                        logging.error(f"Error fetching CVE details: {e}")
                        cve_id, cve_description, cvss_score, exploitability = "N/A", "No CVE information available", "N/A", "N/A"

                    parsed_data.append({
                        "timestamp": match.group("timestamp"),
                        "ip": match.group("ip"),
                        "user": match.group("user"),
                        "event": event,
                        "cve_id": cve_id,
                        "cve_description": cve_description,
                        "cvss_score": cvss_score,
                        "exploitability": exploitability
                    })
                else:
                    skipped_lines += 1
                    logging.debug(f"Skipped unrecognized log line: {line.strip()}")

        # Save parsed data
        if parsed_data:
            df = pd.DataFrame(parsed_data)
            df.to_csv(output_path, index=False)
            logging.info(f"Parsed SSH logs saved to: {output_path}. Skipped {skipped_lines} lines.")
            return 0
        else:
            logging.warning("No suspicious SSH activity found in logs.")
            return 1

    except Exception as e:
        logging.error(f"Error while parsing logs: {e}")
        return 1

if __name__ == "__main__":
    exit(parse_ssh_logs(ssh_log_file, parsed_logs_file))
