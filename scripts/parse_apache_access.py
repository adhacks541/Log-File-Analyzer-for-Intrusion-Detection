import re
import csv
import os
import logging
from datetime import datetime
from map_to_cve import get_cve_details

# Setup logging
log_file = os.path.expanduser('~/log-analyzer/data/parse_apache_access.log')
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,  # Set to DEBUG for detailed output
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Paths
log_paths = [
    '/var/log/apache2/access.log',
    '/opt/lampp/logs/access_log',
    '/var/log/apache2/dvwa_access.log'
]
output_path = os.path.expanduser('~/log-analyzer/data/apache_parsed_with_attacks.csv')

# Regex for parsing Apache logs
log_pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)] "(?P<method>\S+)\s(?P<url>\S+)(?:\s(?P<protocol>\S+))?" (?P<status>\d{3}) (?P<size>\S+)'
)

# Comprehensive attack patterns
attack_patterns = {
    "SQL Injection": [
        r"(?i)\b(select|union|insert|update|delete|drop|alter|create|grant|exec|execute)\b", 
        r"(?i)or\s1=1", r"'?\s*or\s*'1'='1", r"'--", r"'#", r";--", r";#", 
        r"(?i)concat\(", r"(?i)information_schema", r"(?i)load_file", r"(?i)outfile", 
        r"(?i)benchmark\("
    ],
    "XSS": [
        r"(?i)<script.*?>.*?</script>", r"(?i)javascript:.*", r"(?i)on\w+=['\"].*?alert\(", 
        r"(?i)eval\(.*?\)", r"(?i)%3Cscript%3E.*?%3C%2Fscript%3E", r"(?i)document\.cookie", 
        r"(?i)document\.write", r"(?i)innerHTML", r"(?i)location\.href", r"(?i)window\.open",
        r"(?i)alert\(.*?\)", r"(?i)prompt\(.*?\)", r"(?i)console\.log"
    ],
    "LFI (Local File Inclusion)": [
        r"(?i)\.\./", r"(?i)/etc/passwd", r"(?i)file:/", r"(?i)/proc/self/environ", 
        r"(?i)/windows/win\.ini", r"(?i)boot\.ini", r"(?i)/var/www/html", r"(?i)/usr/bin/"
    ],
    "RFI (Remote File Inclusion)": [
        r"(?i)http://.*?(\.txt|\.php|\.pl|\.sh)", r"(?i)https://.*?(\.txt|\.php|\.pl|\.sh)", 
        r"(?i)ftp://.*?(\.txt|\.php|\.pl|\.sh)", r"(?i)data:text/html", r"(?i)php://input",
        r"(?i)file://"
    ],
    "Command Injection": [
        r"(?i)(;|\|\||&&).*", r"(?i)cat\s/etc/passwd", r"(?i)curl|wget\s.*", 
        r"(?i)ls\s", r"(?i)rm\s.*", r"(?i)nc\s", r"(?i)ssh\s.*", r"(?i)echo\s", 
        r"(?i)bash\s", r"(?i)/bin/sh", r"(?i)/bin/bash", r"(?i)python3? ", r"(?i)perl ", 
        r"(?i)whoami", r"(?i)id", r"(?i)chmod"
    ],
    "Web Login Brute Force": [
        r"(?i)/login\.php", r"(?i)/wp-login\.php", r"(?i)/administrator/index\.php", 
        r"(?i)/user", r"(?i)/admin", r"(?i)signin", r"(?i)login.jsp", r"(?i)auth"
    ],
    "SSH Brute Force": [
        r"(?i)sshd:.*Failed password", r"(?i)sshd:.*authentication failure", r"(?i)sshd:.*invalid user", 
        r"(?i)multiple failed attempts", r"(?i)authentication failure"
    ],
    "Path Traversal": [
        r"(?i)\.\./\.\./", r"(?i)\.\./etc/passwd", r"(?i)\.\./windows", r"(?i)\.\./system32", 
        r"(?i)\.\./var/log", r"(?i)\.\./home", r"(?i)/root", r"(?i)\.\./boot.ini"
    ],
    "Denial of Service (DoS)": [
        r"(?i)(ping\s.*?flood|slowloris|hping3|smurf)", r"(?i)/null", r"(?i)/con/con", 
        r"(?i)/aux/aux", r"(?i)/dev/null"
    ],
    "Directory Listing": [
        r"(?i)index of /", r"(?i)directory listing", r"(?i)/cgi-bin/", r"(?i)/admin/", 
        r"(?i)/server-status", r"(?i)/backup/"
    ],
    "User Enumeration": [
        r"(?i)/user/.*", r"(?i)/profile/.*", r"(?i)/id=.*", r"(?i)/member/.*"
    ],
    "CSRF (Cross-Site Request Forgery)": [
        r"(?i)csrf_token", r"(?i)xsrf_token", r"(?i)fake_token"
    ],
    "Default Patterns (Backdoor or Default Credentials)": [
        r"(?i)/phpmyadmin", r"(?i)/admin", r"(?i)/config.php", r"(?i)wp-config.php", 
        r"(?i)/etc/shadow", r"(?i)/shell.php"
    ],
    "General Access": [
        r".*"  # Default fallback pattern
    ]
}


parsed_entries = []
skipped_lines = 0

def parse_apache_logs():
    """Parse Apache logs for suspicious activities."""
    global skipped_lines
    for log_path in log_paths:
        if not os.path.exists(log_path):
            logging.warning(f"Log file not found: {log_path}")
            continue

        with open(log_path, 'r') as logfile:
            for line in logfile:
                logging.debug(f"Processing log line: {line.strip()}")
                match = log_pattern.match(line)
                if match:
                    data = match.groupdict()

                    # Convert timestamp
                    try:
                        dt_object = datetime.strptime(data['timestamp'].split()[0], "%d/%b/%Y:%H:%M:%S")
                        data['timestamp'] = dt_object.isoformat()
                    except Exception as e:
                        logging.warning(f"Failed to parse timestamp: {e}")
                        continue

                    # Detect attack type
                    attack_type = "General Access"
                    for atk, patterns in attack_patterns.items():
                        if any(re.search(p, data['url'], re.IGNORECASE) for p in patterns):
                            logging.debug(f"Attack pattern matched: {atk}")
                            attack_type = atk
                            break

                    # Map CVE with error handling
                    try:
                        cve_details = get_cve_details(attack_type)
                        if isinstance(cve_details, tuple) and len(cve_details) >= 2:
                            cve_id, cve_description = cve_details[0], cve_details[1]
                            cvss_score = cve_details[2] if len(cve_details) > 2 else "N/A"
                            exploitability = cve_details[3] if len(cve_details) > 3 else "N/A"
                        else:
                            cve_id, cve_description, cvss_score, exploitability = "N/A", "Invalid CVE response", "N/A", "N/A"
                    except Exception as e:
                        logging.error(f"Error mapping CVE: {e}")
                        cve_id, cve_description, cvss_score, exploitability = "N/A", "Error during CVE lookup", "N/A", "N/A"

                    # Add the entry
                    parsed_entries.append({
                        'ip': data['ip'],
                        'timestamp': data['timestamp'],
                        'method': data['method'],
                        'url': data['url'],
                        'protocol': data.get('protocol', 'N/A'),
                        'status': data['status'],
                        'size': data['size'],
                        'attack_type': attack_type,
                        'cve_id': cve_id,
                        'cve_description': cve_description,
                        'cvss_score': cvss_score,
                        'exploitability': exploitability
                    })
                else:
                    skipped_lines += 1
                    logging.debug(f"Skipped unrecognized log line: {line.strip()}")

    # Save to CSV
    if parsed_entries:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = [
                'ip', 'timestamp', 'method', 'url', 'protocol', 
                'status', 'size', 'attack_type', 'cve_id', 
                'cve_description', 'cvss_score', 'exploitability'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(parsed_entries)
        logging.info(f"Saved {len(parsed_entries)} entries. Skipped {skipped_lines} lines.")
        return 0
    else:
        logging.warning("No valid log entries found.")
        return 1

if __name__ == "__main__":
    exit(parse_apache_logs())
