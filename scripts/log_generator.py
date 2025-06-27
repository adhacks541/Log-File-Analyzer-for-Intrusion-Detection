import os
import random
import time
from datetime import datetime

# Paths
output_dir = os.path.expanduser('~/log-analyzer/logs/')
os.makedirs(output_dir, exist_ok=True)
ssh_log_path = os.path.join(output_dir, 'ssh_logs.txt')
apache_log_path = os.path.join(output_dir, 'apache_access.log')

# SSH Log Simulation
def generate_ssh_logs():
    actions = ["Failed password", "Accepted password"]
    users = ["root", "admin", "user", "test", "invaliduser"]
    ips = ["192.168.1.1", "203.0.113.5", "10.0.0.2", "172.16.254.1", "45.33.32.156"]
    
    with open(ssh_log_path, 'a') as f:
        for _ in range(100):  # Generate 100 log entries
            timestamp = datetime.now().strftime('%b %d %H:%M:%S')
            action = random.choice(actions)
            user = random.choice(users)
            ip = random.choice(ips)
            log_line = f"{timestamp} myhost sshd[12345]: {action} for {user} from {ip} port 22 ssh2\n"
            f.write(log_line)

# Apache Log Simulation
def generate_apache_logs():
    methods = ["GET", "POST", "PUT", "DELETE"]
    statuses = [200, 301, 400, 403, 404, 500]
    urls = [
        "/index.html", "/login", "/admin", "/api/data", "/search?q=test", "/etc/passwd"
    ]
    ips = ["192.168.1.1", "203.0.113.5", "10.0.0.2", "172.16.254.1", "45.33.32.156"]
    
    with open(apache_log_path, 'a') as f:
        for _ in range(100):  # Generate 100 log entries
            timestamp = datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z')
            ip = random.choice(ips)
            method = random.choice(methods)
            url = random.choice(urls)
            status = random.choice(statuses)
            log_line = f"{ip} - - [{timestamp}] \"{method} {url} HTTP/1.1\" {status} {random.randint(100, 2000)}\n"
            f.write(log_line)

if __name__ == "__main__":
    print("Generating simulated logs...")
    generate_ssh_logs()
    generate_apache_logs()
    print(f"SSH logs saved to {ssh_log_path}")
    print(f"Apache logs saved to {apache_log_path}")
