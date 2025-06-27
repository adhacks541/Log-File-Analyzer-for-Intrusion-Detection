import os
import pandas as pd
import logging

# Setup logging
logging.basicConfig(
    filename=os.path.expanduser('~/log-analyzer/data/detect_intrusions.log'),
    level=logging.DEBUG,  # Set to DEBUG for more detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# File paths
parsed_log_path = os.path.expanduser('~/log-analyzer/data/parsed_logs.csv')
apache_parsed_path = os.path.expanduser('~/log-analyzer/data/apache_parsed_with_attacks.csv')
final_report_path = os.path.expanduser('~/log-analyzer/data/final_report.csv')

def detect_intrusions():
    """Detect intrusions from SSH and Apache logs."""
    logging.info("Starting intrusion detection process...")

    # Check if required files exist
    if not os.path.exists(parsed_log_path):
        logging.error(f"SSH log file not found: {parsed_log_path}")
        return 1
    if not os.path.exists(apache_parsed_path):
        logging.error(f"Apache log file not found: {apache_parsed_path}")
        return 1

    try:
        # Load SSH logs
        logging.debug(f"Loading SSH logs from {parsed_log_path}")
        ssh_df = pd.read_csv(parsed_log_path)

        # Add brute force detection flag
        ssh_df['is_brute_force'] = ssh_df['event'].str.contains('Failed', case=False, na=False)
        logging.debug("Added brute force detection flag to SSH logs.")

        # Load Apache logs
        logging.debug(f"Loading Apache logs from {apache_parsed_path}")
        apache_df = pd.read_csv(apache_parsed_path)

        # Add attack detection flag
        apache_df['is_attack'] = apache_df['attack_type'] != "General Access"
        logging.debug("Added attack detection flag to Apache logs.")

        # Merge the data
        final_df = pd.concat([ssh_df, apache_df], ignore_index=True, sort=False)
        logging.debug("Combined SSH and Apache data.")

        # Save final report
        os.makedirs(os.path.dirname(final_report_path), exist_ok=True)
        final_df.to_csv(final_report_path, index=False)
        logging.info(f"Final intrusion report saved to: {final_report_path}")
        logging.debug(f"Final report contains {len(final_df)} entries.")
        return 0

    except Exception as e:
        logging.error(f"Error during intrusion detection: {e}")
        return 1

if __name__ == "__main__":
    exit(detect_intrusions())
