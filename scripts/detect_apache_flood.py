import pandas as pd
import os
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(filename=os.path.expanduser('~/log-analyzer/data/apache_flood_detection.log'),
                    level=logging.INFO,
                    format='%(asctime)s - %(message)s')

# File paths
input_file = os.path.expanduser('~/log-analyzer/data/apache_parsed_with_attacks.csv')
output_file = os.path.expanduser('~/log-analyzer/data/apache_flood_detected.csv')

# Thresholds
REQUEST_THRESHOLD = 100  # Requests per minute from a single IP

def detect_flooding(input_path, output_path, threshold):
    """Detect potential HTTP flood attacks."""
    if not os.path.exists(input_path):
        logging.error(f"Input file not found: {input_path}")
        return

    try:
        # Load parsed Apache logs
        df = pd.read_csv(input_path)

        # Convert timestamp to datetime and group requests per IP per minute
        df['minute'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H:%M')
        flood_counts = df.groupby(['ip', 'minute']).size().reset_index(name='count')

        # Identify IPs exceeding the threshold
        flood_alerts = flood_counts[flood_counts['count'] > threshold]

        if not flood_alerts.empty:
            # Save flood alerts to CSV
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            flood_alerts.to_csv(output_path, index=False)
            logging.info(f"Flooding detected from {len(flood_alerts['ip'].unique())} IP(s).")
            logging.info(f"Flood alerts saved to {output_path}")

            print(f"[+] HTTP flood attack detected! {len(flood_alerts['ip'].unique())} IP(s) flagged.")
        else:
            logging.info("No flood attacks detected.")
            print("[*] No HTTP flood attacks detected.")

    except Exception as e:
        logging.error(f"Error during flood detection: {e}")

if __name__ == "__main__":
    detect_flooding(input_file, output_file, REQUEST_THRESHOLD)
