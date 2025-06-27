import streamlit as st
import pandas as pd
import os
import geoip2.database
from glob import glob

# Configuration
st.set_page_config(page_title="Intrusion Detection Dashboard", layout="wide")

# Paths to data files
suspicious_path = os.path.expanduser('~/log-analyzer/data/suspicious_activity.csv')
ssh_parsed_path = os.path.expanduser('~/log-analyzer/data/parsed_logs.csv')
apache_parsed_path = os.path.expanduser('~/log-analyzer/data/apache_parsed_with_attacks.csv')
final_report_path = os.path.expanduser('~/log-analyzer/data/final_report.csv')

# Load data function
def load_data(path):
    if os.path.exists(path):
        return pd.read_csv(path)
    return pd.DataFrame()

# Load datasets
suspicious_data = load_data(suspicious_path)
ssh_data = load_data(ssh_parsed_path)
apache_data = load_data(apache_parsed_path)
final_data = load_data(final_report_path)

# Dashboard Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Overview", "🖥️ SSH Logs", "🌐 Apache Logs", "🗺️ Attack Map", "📁 Raw Data"
])

# Overview Tab
with tab1:
    st.header("📊 Security Overview")

    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", len(final_data))
    col2.metric("Unique IPs", final_data['ip'].nunique() if 'ip' in final_data.columns else 0)
    col3.metric("Unique CVEs", final_data['cve_id'].nunique() if 'cve_id' in final_data.columns else 0)
    col4.metric("Critical Events", len(final_data[final_data['severity'] == 'Critical']) if 'severity' in final_data.columns else 0)

    # Attack Timeline
    if not final_data.empty:
        st.subheader("🧩 Attack Timeline")
        final_data['timestamp'] = pd.to_datetime(final_data['timestamp'], errors='coerce')
        timeline = final_data.groupby(final_data['timestamp'].dt.date).size()
        st.line_chart(timeline)

    # Severity Insights
    if 'severity' in final_data.columns:
        st.subheader("🔥 Attack Severity Distribution")
        severity_counts = final_data['severity'].value_counts()
        st.bar_chart(severity_counts)

# SSH Logs Tab
with tab2:
    st.header("🖥️ SSH Intrusion Attempts")
    if not ssh_data.empty:
        if {'ip', 'event', 'timestamp', 'cve_id', 'cve_description', 'cvss_score', 'exploitability'}.issubset(ssh_data.columns):
            st.dataframe(ssh_data[['timestamp', 'ip', 'event', 'cve_id', 'cve_description', 'cvss_score', 'exploitability']])
            st.bar_chart(ssh_data['ip'].value_counts().head(10))
        else:
            st.warning("SSH log columns are incomplete. Ensure the parsing script outputs all required fields.")
    else:
        st.info("No SSH logs available.")

# Apache Logs Tab
with tab3:
    st.header("🌐 Apache Intrusion Attempts")
    if not apache_data.empty:
        if {'ip', 'timestamp', 'url', 'status', 'cve_id', 'cve_description', 'cvss_score', 'exploitability'}.issubset(apache_data.columns):
            st.dataframe(apache_data[['timestamp', 'ip', 'url', 'status', 'cve_id', 'cve_description', 'cvss_score', 'exploitability']])
            st.bar_chart(apache_data['ip'].value_counts().head(10))
        else:
            st.warning("Apache log columns are incomplete. Ensure the parsing script outputs all required fields.")
    else:
        st.info("No Apache logs available.")


# Attack Map Tab
with tab4:
    st.header("🗺️ Geographical Attack Map")
    mmdb_candidates = glob(os.path.expanduser("~/log-analyzer/geo/GeoLite2-City.mmdb"))
    if mmdb_candidates:
        try:
            reader = geoip2.database.Reader(mmdb_candidates[0])

            def get_location(ip):
                try:
                    res = reader.city(ip)
                    return {
                        "ip": ip,
                        "city": res.city.name,
                        "country": res.country.name,
                        "lat": res.location.latitude,
                        "lon": res.location.longitude
                    }
                except:
                    return None

            locations = [get_location(ip) for ip in final_data['ip'].dropna().unique()]
            geo_df = pd.DataFrame([loc for loc in locations if loc])

            if not geo_df.empty:
                st.map(geo_df[['lat', 'lon']])
            else:
                st.info("No geolocation data available.")
        except Exception as e:
            st.error(f"Error loading GeoLite2 database: {e}")
    else:
        st.warning("GeoLite2 database not found. Please install for geographical insights.")

# Raw Data Tab
with tab5:
    st.header("📁 Raw Event Data")
    if not final_data.empty:
        st.dataframe(final_data)
    else:
        st.info("No data available for display.")
