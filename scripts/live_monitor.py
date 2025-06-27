import time
import re
import csv
import os
import smtplib
from datetime import datetime
from email.message import EmailMessage
from dotenv import load_dotenv
import logging
from map_to_cve import get_cve_details

# Setup logging
monitor_log = os.path.expanduser('~/log-analyzer/data/monitor.log')
os.makedirs(os.path.dirname(monitor_log), exist_ok=True)
logging.basicConfig(filename=monitor_log, level=logging.INFO, format='%(asctime)s - %(message)s')

# Load environment variables
load_dotenv(dotenv_path=os.path.expanduser('~/log-analyzer/.env'))
email_sender = os.getenv("EMAIL_SENDER")
email_password = os.getenv("EMAIL_PASSWORD")
email_receiver = os.getenv("EMAIL_RECEIVER")

# Log file paths
ssh_log_file = "/var/log/auth.log"
apache_log_file = "/opt/lampp/logs/access_log"
report_file = os.path.expanduser('~/log-analyzer/data/final_report.csv')

# Patterns for log detection
ssh_pattern = re.compile(r"(?P<timestamp>\w{3} \d+ \d+:\d+:\d+).*Failed password.*from (?P<ip>[^\s]+)")
apache_patterns = {
    "SQL Injection": re.compile(r"(select\s.+\sfrom|union\s+select|or\s+1=1|(' OR '1'='1'))", re.IGNORECASE),
    "XSS": re.compile(r"(<script>|onerror=|alert\()", re.IGNORECASE),
    "LFI/RFI": re.compile(r"(\.\./|/etc/passwd|php://)", re.IGNORECASE),
    "Command Injection": re.compile(r"(;|&&|\|\||\$\(.*\)|\{.*\})", re.IGNORECASE)
}

# Track already seen lines
seen_ssh_lines = set()
seen_apache_lines = set()

def send_email(alert_type, ip, cve_id, description):
    """Send email alerts for detected intrusions."""
    if not all([email_sender, email_password, email_receiver]):
        logging.error("Email credentials are missing. Cannot send alerts.")
        return

    msg = EmailMessage()
    msg['Subject'] = f"🚨 Intrusion Alert: {alert_type} detected"
    msg['From'] = email_sender
    msg['To'] = email_receiver
    body = f"""
    Alert Type: {alert_type}
    IP Address: {ip}
    CVE ID: {cve_id}
    Description: {description}
    Timestamp: {datetime.now().isoformat()}
    """
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(email_sender, email_password)
            smtp.send_message(msg)
        logging.info(f"Email alert sent for {ip}")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def monitor_logs():
    """Monitor SSH and Apache logs for suspicious activities."""
    logging.info("Starting live monitoring... 🚀")

    if not all([os.path.exists(ssh_log_file), os.path.exists(apache_log_file)]):
        logging.error("One or more log files are missing.")
        return

    with open(ssh_log_file, 'r') as ssh_f, open(apache_log_file, 'r') as apache_f:
        # Move to the end of the log files
        ssh_f.seek(0, os.SEEK_END)
        apache_f.seek(0, os.SEEK_END)

        while True:
            ssh_line = ssh_f.readline()
            apache_line = apache_f.readline()

            # Process SSH logs
            if ssh_line and ssh_line not in seen_ssh_lines:
                seen_ssh_lines.add(ssh_line)
                ssh_match = ssh_pattern.search(ssh_line)
                if ssh_match:
                    ip = ssh_match.group('ip')
                    timestamp = datetime.now().isoformat()
                    cve_id, cve_description = get_cve_details("Brute Force")
                    send_email("SSH Intrusion", ip, cve_id, cve_description)
                    logging.info(f"Detected SSH intrusion from {ip}.")

                    # Write to the final report
                    write_to_report(timestamp, ip, "SSH Intrusion", cve_id, cve_description)

            # Process Apache logs
            if apache_line and apache_line not in seen_apache_lines:
                seen_apache_lines.add(apache_line)
                for attack_type, pattern in apache_patterns.items():
                    if pattern.search(apache_line):
                        ip = apache_line.split()[0] if apache_line.split() else "Unknown"
                        timestamp = datetime.now().isoformat()
                        cve_id, cve_description = get_cve_details(attack_type)
                        send_email(f"Apache {attack_type}", ip, cve_id, cve_description)
                        logging.info(f"Detected Apache {attack_type} attack from {ip}.")

                        # Write to the final report
                        write_to_report(timestamp, ip, f"Apache {attack_type}", cve_id, cve_description)
                        break

            time.sleep(1)

def write_to_report(timestamp, ip, alert_type, cve_id, description):
    """Append an entry to the final report."""
    try:
        with open(report_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([timestamp, ip, alert_type, cve_id, description])
    except Exception as e:
        logging.error(f"Failed to write to report: {e}")

if __name__ == "__main__":
    monitor_logs()
