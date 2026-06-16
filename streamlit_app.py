import os
import re
import json
import streamlit as st
from cloud_risk_scanner import (
    get_subdomains,
    deduplicate_subdomains,
    analyze_subdomains,
    score_risk,
    generate_report,
    SHODAN_API_KEY,
    GITHUB_TOKEN,
)

st.set_page_config(page_title="Attack Surface Mapper", layout="wide", page_icon="☁️")

APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


def require_auth():
    if not APP_PASSWORD:
        return
    if st.session_state.get("authenticated"):
        return
    st.title("Attack Surface Mapper")
    st.caption("Enter the shared password to access this tool.")
    password = st.text_input("Password", type="password")
    if st.button("Sign in"):
        if password == APP_PASSWORD:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Invalid password.")
    st.stop()


require_auth()

st.title("Attack Surface Mapper")
st.markdown(
    "Scan a company's public cloud footprint for exposed credentials, storage buckets, "
    "dangling subdomains, and risky open ports."
)

with st.expander("Authorized use only", expanded=False):
    st.markdown(
        "Only scan domains you own or have **written permission** to test. "
        "Unauthorized scanning may violate laws or contracts."
    )

missing_keys = []
if not SHODAN_API_KEY:
    missing_keys.append("SHODAN_API_KEY")
if not GITHUB_TOKEN:
    missing_keys.append("GITHUB_TOKEN")
if missing_keys:
    st.warning(
        f"Missing API keys: {', '.join(missing_keys)}. "
        "Shodan and GitHub checks will be skipped until keys are set in Render."
    )

authorized = st.checkbox("I have permission to scan the target domain")
domain = st.text_input("Company domain", placeholder="example.com").strip().lower()

if st.button("Run scan", type="primary", disabled=not authorized):
    if not domain or not DOMAIN_PATTERN.match(domain):
        st.error("Enter a valid domain (e.g. example.com).")
    else:
        progress_bar = st.progress(0, text="Discovering subdomains...")
        status = st.empty()

        subdomains = get_subdomains(domain)
        limited = deduplicate_subdomains(subdomains)[:50]

        if not limited:
            st.warning("No subdomains found. Try another domain or check network access.")
        else:
            status.info(f"Found {len(limited)} subdomains. Analyzing...")

            def on_progress(current, total, subdomain):
                progress_bar.progress(
                    current / total,
                    text=f"Analyzing {current}/{total}: {subdomain}",
                )

            results, buckets, leaks, credentials = analyze_subdomains(
                limited, domain, progress_callback=on_progress
            )
            scores = score_risk(results, buckets, leaks, credentials)
            report = generate_report(domain, results, scores, buckets, leaks, credentials)

            progress_bar.empty()
            status.empty()
            st.success(f"Scan complete — {len(results)} subdomains analyzed.")

            st.subheader("Risk scores")
            st.bar_chart(scores)

            st.subheader("Discovered subdomains")
            st.dataframe(results, use_container_width=True)

            if credentials:
                st.subheader("Credentials found")
                st.json(credentials)

            if buckets:
                st.subheader("Exposed buckets")
                for bucket_url in buckets:
                    st.markdown(f"- [{bucket_url}]({bucket_url})")

            if leaks:
                st.subheader("GitHub links")
                for leak in leaks:
                    st.markdown(f"- [{leak['url']}]({leak['url']})")

            st.subheader("Download report")
            st.download_button(
                "Download JSON",
                data=json.dumps(report, indent=2),
                file_name=f"{domain}_scan.json",
                mime="application/json",
            )
