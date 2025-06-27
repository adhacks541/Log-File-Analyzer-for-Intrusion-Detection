import os
import pandas as pd
import logging

# File paths
final_csv_file = os.path.expanduser('~/log-analyzer/data/final_report.csv')
final_excel_file = os.path.expanduser('~/log-analyzer/data/final_report.xlsx')
report_log = os.path.expanduser('~/log-analyzer/data/report_generation.log')

# Setup logging
os.makedirs(os.path.dirname(report_log), exist_ok=True)
logging.basicConfig(
    filename=report_log,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Severity mapping (placeholder for actual CVSS-based scoring)
SEVERITY_MAPPING = {
    "CVE-2021-1234": "High",
    "CVE-2020-1234": "Medium",
    "CVE-2020-8260": "High",
    "CVE-2019-14287": "Critical",
    "CVE-2020-14145": "Medium",
    "CVE-2021-41773": "High",
}

def generate_summary(df):
    """Generate and log summary statistics."""
    total_entries = len(df)
    unique_ips = df['ip'].nunique()
    unique_cves = df['cve_id'].nunique()

    logging.info("===== Incident Summary =====")
    logging.info(f"Total Incidents: {total_entries}")
    logging.info(f"Unique IPs: {unique_ips}")
    logging.info(f"Unique CVEs: {unique_cves}")
    logging.info("============================")

def prioritize_vulnerabilities(df):
    """Add a severity column based on CVE mapping."""
    df['severity'] = df['cve_id'].map(SEVERITY_MAPPING).fillna("Low")
    return df

def generate_report():
    """Generate the final security report."""
    try:
        # Ensure the CSV file exists
        if not os.path.exists(final_csv_file):
            logging.error("Final CSV file not found. Skipping report generation.")
            return 1

        # Load the final report data
        df = pd.read_csv(final_csv_file)

        # Prioritize vulnerabilities
        df = prioritize_vulnerabilities(df)

        # Save to Excel format
        df.to_excel(final_excel_file, index=False)
        logging.info(f"Final report saved to {final_excel_file}")

        # Generate summary statistics
        generate_summary(df)
        logging.info("Report generation completed successfully.")
        return 0
    except Exception as e:
        logging.error(f"Error generating final report: {e}")
        return 1

if __name__ == "__main__":
    exit(generate_report())
