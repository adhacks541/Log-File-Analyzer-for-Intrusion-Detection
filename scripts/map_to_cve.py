import os
import pandas as pd
import logging
import requests
import json

# File paths
report_log = os.path.expanduser('~/log-analyzer/data/report_generation.log')
cache_file = os.path.expanduser('~/log-analyzer/data/cve_cache.json')

# NVD API Details
API_KEY = os.getenv('NVD_API_KEY', '')  # Retrieve API key from environment variable
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Comprehensive STATIC_CVE_MAP
STATIC_CVE_MAP = {
    "Brute Force": ("CVE-2020-14145", "SSH brute force attack detected."),
    "Web Login Brute Force": ("CVE-2021-27850", "Web login brute force attack detected."),
    "Apache Flood": ("CVE-2020-8260", "Denial of Service via Apache flood."),
    "Privilege Escalation": ("CVE-2019-14287", "Privilege escalation vulnerability."),
    "XSS": ("CVE-2020-1234", "Cross-site scripting detected."),
    "SQL Injection": ("CVE-2019-15107", "SQL injection attack detected."),
    "Command Injection": ("CVE-2021-3156", "Command injection vulnerability."),
    "LFI": ("CVE-2017-9841", "Local File Inclusion detected."),
    "General Access": ("CVE-2006-0664", "General vulnerability detected.")
}


# Setup logging
os.makedirs(os.path.dirname(report_log), exist_ok=True)
logging.basicConfig(
    filename=report_log,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Load or initialize the cache
if os.path.exists(cache_file):
    with open(cache_file, 'r') as f:
        cve_cache = json.load(f)
else:
    cve_cache = {}

def save_cache():
    """Save the current cache to disk."""
    try:
        with open(cache_file, 'w') as f:
            json.dump(cve_cache, f)
        logging.info("Cache saved successfully.")
    except Exception as e:
        logging.error(f"Failed to save cache: {e}")

def get_cve_details(keyword, severity="CRITICAL"):
    """
    Retrieve CVE details from the NVD API or static mappings.
    :param keyword: The keyword to search for CVE.
    :param severity: Optional filter by severity (e.g., CRITICAL, HIGH).
    :return: (CVE ID, CVE Description, CVSS Score, Exploitability)
    """
    # Check the cache first
    cache_key = f"{keyword}_{severity}"
    if cache_key in cve_cache:
        logging.info(f"Cache hit for {cache_key}")
        return cve_cache[cache_key]

    # Check static mappings
    if keyword in STATIC_CVE_MAP:
        logging.info(f"Static mapping hit for {keyword}")
        result = STATIC_CVE_MAP[keyword] + ("N/A", "N/A")
        cve_cache[cache_key] = result
        save_cache()
        return result

    # Dynamic mapping via NVD API
    try:
        params = {
            "keywordSearch": keyword,
            "cvssV3Severity": severity,
            "resultsPerPage": 1
        }
        if API_KEY:
            params["apiKey"] = API_KEY
        response = requests.get(BASE_URL, params=params, timeout=10)
        response.raise_for_status()

        data = response.json()
        if data.get("totalResults", 0) > 0:
            cve = data["vulnerabilities"][0]["cve"]
            cvss_score = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
            exploitability = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("exploitabilityScore", "N/A")
            result = (cve["id"], cve["descriptions"][0]["value"], cvss_score, exploitability)

            cve_cache[cache_key] = result
            save_cache()
            logging.info(f"Dynamic mapping success for {keyword}")
            return result
    except requests.RequestException as e:
        logging.error(f"API error for keyword '{keyword}': {e}")
    except Exception as e:
        logging.error(f"Unexpected error for keyword '{keyword}': {e}")

    # Fallback to default invalid response
    logging.warning(f"Unable to map CVE for {keyword}.")
    return "N/A", "Invalid CVE response", "N/A", "N/A"

def enhance_cve_data(df):
    """
    Enhance the DataFrame by mapping event categories to CVEs.
    :param df: DataFrame containing log data.
    :return: Enhanced DataFrame with CVE details.
    """
    for idx, row in df.iterrows():
        if pd.isna(row.get("cve_id")) or row["cve_id"] == "N/A":
            event_category = row.get("event_category", "Unknown")
            cve_id, cve_description, cvss_score, exploitability = get_cve_details(event_category)
            df.at[idx, "cve_id"] = cve_id
            df.at[idx, "cve_description"] = cve_description
            df.at[idx, "cvss_score"] = cvss_score
            df.at[idx, "exploitability"] = exploitability
    return df

if __name__ == "__main__":
    print("[!] This script is intended to be used as a module.")
