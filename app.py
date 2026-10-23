"""
CyberShield – Rule-Based Suspicious Login Detection and Security Monitoring Dashboard
======================================================================================
Author  : Kumari Shambhavi
Project : IBM SkillsBuild Cyber Security 2026 (BharatCares)
Version : 1.4

PURPOSE
-------
This is a beginner-friendly, simulated cybersecurity monitoring dashboard.
It analyses fictional login activity data and flags IP addresses that show
a suspicious pattern of repeated failed login attempts.

IMPORTANT DISCLAIMER
--------------------
- All data is entirely simulated/fictional. No real users, credentials, or
  systems are represented.
- This project does NOT perform any form of penetration testing or real attack.
- Detecting a suspicious pattern does NOT prove a cyberattack has occurred.
  Every alert requires further human investigation.
- Built for educational purposes only.

HOW TO RUN
----------
    streamlit run app.py
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import random

# ===========================================================================
# Page Configuration
# ===========================================================================
st.set_page_config(
    page_title="CyberShield Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# ===========================================================================
# Custom CSS — Dark Cybersecurity Theme
# ===========================================================================
st.markdown("""
    <style>
        /* Main background */
        .stApp {
            background-color: #0d1117;
            color: #c9d1d9;
        }

        /* Sidebar */
        section[data-testid="stSidebar"] {
            background-color: #161b22;
            border-right: 1px solid #30363d;
        }

        /* Metric cards */
        div[data-testid="metric-container"] {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }

        div[data-testid="metric-container"] label {
            color: #8b949e !important;
            font-size: 0.85rem;
        }

        div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
            color: #58a6ff !important;
            font-size: 2rem;
        }

        /* Headings */
        h1 { color: #58a6ff !important; }
        h2, h3 { color: #c9d1d9 !important; }

        /* Dataframe */
        .stDataFrame { background-color: #161b22; }

        /* Divider */
        hr { border-color: #30363d; }

        /* Alert cards */
        .alert-card {
            background-color: #161b22;
            border-radius: 8px;
            padding: 14px 18px;
            margin-bottom: 10px;
            border-left: 5px solid #30363d;
        }
        .alert-high   { border-left-color: #da3633; }
        .alert-medium { border-left-color: #d29922; }
        .alert-low    { border-left-color: #238636; }

        /* Risk badges */
        .badge {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.78rem;
            font-weight: 600;
            letter-spacing: 0.04em;
        }
        .badge-high   { background-color: #da3633; color: #fff; }
        .badge-medium { background-color: #d29922; color: #fff; }
        .badge-low    { background-color: #238636; color: #fff; }

        /* Info box override for dark theme */
        div[data-testid="stNotification"] {
            background-color: #1c2333;
            border: 1px solid #30363d;
        }
    </style>
""", unsafe_allow_html=True)

# ===========================================================================
# Simulated Login Activity Dataset
# ===========================================================================
# The dataset is entirely fictional and generated for educational/demo purposes.
# It does NOT contain real credentials or real authentication events.
#
# Three deterministic IP groups are included so all test cases can be shown:
#
#   TEST 1 — 10.99.0.1   →  3 failed attempts  → NOT flagged (below threshold)
#   TEST 2 — 45.33.32.156 → 6 failed attempts  → Medium Risk
#   TEST 3 — 185.220.101.5→ 9 failed attempts  → High Risk
# ===========================================================================

random.seed(42)

USERNAMES = ["alice", "bob", "charlie", "diana", "eve", "frank", "grace", "hank"]
# Raw login results contain ONLY "Success" and "Failed".
# "Suspicious" is a detection outcome, never a raw login status.
STATUSES  = ["Success", "Success", "Success", "Failed"]
IP_POOL   = [
    "192.168.1.10", "10.0.0.5",    "172.16.0.3",
    "203.0.113.42", "198.51.100.7", "192.0.2.88",
    "185.220.101.5", "45.33.32.156",
]


def generate_login_data(n: int = 50) -> pd.DataFrame:
    """Generate n random, fictional login records."""
    records = []
    base_time = datetime(2024, 6, 1, 8, 0, 0)
    for _ in range(n):
        timestamp = base_time + timedelta(minutes=random.randint(0, 1440))
        records.append({
            "Timestamp":  timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "Username":   random.choice(USERNAMES),
            "IP Address": random.choice(IP_POOL),
            "Status":     random.choice(STATUSES),
        })
    records.sort(key=lambda x: x["Timestamp"])
    return pd.DataFrame(records)


df = generate_login_data(50)

# ---------------------------------------------------------------------------
# Deterministic seed records — guarantee all three test cases are present.
# All records are fully fictional.
# ---------------------------------------------------------------------------
seed_records = [
    # --- TEST 1: 10.99.0.1 — exactly 3 failed attempts ---
    # Expected: does NOT appear in Security Alerts (below threshold of 5).
    {"Timestamp": "2024-06-01 06:50:00", "Username": "hank",    "IP Address": "10.99.0.1",     "Status": "Failed"},
    {"Timestamp": "2024-06-01 06:51:00", "Username": "hank",    "IP Address": "10.99.0.1",     "Status": "Failed"},
    {"Timestamp": "2024-06-01 06:52:00", "Username": "grace",   "IP Address": "10.99.0.1",     "Status": "Failed"},

    # --- TEST 2: 45.33.32.156 — exactly 6 failed attempts ---
    # Expected: appears in Security Alerts with Risk = Medium.
    {"Timestamp": "2024-06-01 07:10:00", "Username": "eve",     "IP Address": "45.33.32.156",  "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:11:00", "Username": "frank",   "IP Address": "45.33.32.156",  "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:12:00", "Username": "eve",     "IP Address": "45.33.32.156",  "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:13:00", "Username": "grace",   "IP Address": "45.33.32.156",  "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:14:00", "Username": "eve",     "IP Address": "45.33.32.156",  "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:15:00", "Username": "frank",   "IP Address": "45.33.32.156",  "Status": "Failed"},

    # --- TEST 3: 185.220.101.5 — exactly 9 failed attempts ---
    # Expected: appears in Security Alerts with Risk = High.
    {"Timestamp": "2024-06-01 07:01:00", "Username": "alice",   "IP Address": "185.220.101.5", "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:02:00", "Username": "bob",     "IP Address": "185.220.101.5", "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:03:00", "Username": "charlie", "IP Address": "185.220.101.5", "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:04:00", "Username": "alice",   "IP Address": "185.220.101.5", "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:05:00", "Username": "diana",   "IP Address": "185.220.101.5", "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:06:00", "Username": "alice",   "IP Address": "185.220.101.5", "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:07:00", "Username": "bob",     "IP Address": "185.220.101.5", "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:08:00", "Username": "charlie", "IP Address": "185.220.101.5", "Status": "Failed"},
    {"Timestamp": "2024-06-01 07:09:00", "Username": "diana",   "IP Address": "185.220.101.5", "Status": "Failed"},
]

df = pd.concat([df, pd.DataFrame(seed_records)], ignore_index=True)
df = df.sort_values("Timestamp").reset_index(drop=True)

# ===========================================================================
# Rule-Based Suspicious IP Detection
# Always runs on the FULL dataset — sidebar filters never affect this logic.
#
# Rule:
#   An IP address is flagged as suspicious when it has 5 or more failed
#   login attempts.
#
# Risk levels:
#   < 5 failed attempts  →  not flagged
#   5–8 failed attempts  →  Medium Risk
#   9+  failed attempts  →  High Risk
# ===========================================================================
FAILED_THRESHOLD = 5

failed_df = df[df["Status"] == "Failed"]

ip_fail_counts = (
    failed_df.groupby("IP Address")
    .agg(
        failed_attempts   =("Status",   "count"),
        usernames_involved=("Username", lambda x: ", ".join(sorted(set(x)))),
    )
    .reset_index()
)

suspicious_ips = ip_fail_counts[
    ip_fail_counts["failed_attempts"] >= FAILED_THRESHOLD
].copy()


def get_risk_level(count: int) -> str:
    """Map a failed-attempt count to a risk level label."""
    if count >= 9:
        return "High"
    elif count >= 5:
        return "Medium"
    else:
        return "Low"


suspicious_ips["Risk Level"] = suspicious_ips["failed_attempts"].apply(get_risk_level)
suspicious_ips["Reason"] = (
    "IP address recorded "
    + suspicious_ips["failed_attempts"].astype(str)
    + " failed login attempt(s), meeting or exceeding the suspicious activity "
    "threshold of " + str(FAILED_THRESHOLD) + "."
)

# ===========================================================================
# Computed Metrics  (always derived from the full, unfiltered dataset)
# ===========================================================================
total_logins          = len(df)
successful_logins     = len(df[df["Status"] == "Success"])
failed_logins         = len(df[df["Status"] == "Failed"])
suspicious_activities = len(suspicious_ips)

# ===========================================================================
# Sidebar — Filters
# ===========================================================================
with st.sidebar:
    st.markdown("## 🔍 Filters")
    st.markdown("---")

    st.markdown("**Login Result**")
    st.caption("Filters the Login Activity Log below.")
    login_result_filter = st.radio(
        label="Login Result",
        options=["All", "Success", "Failed"],
        index=0,
        label_visibility="collapsed",
    )

    st.markdown("---")

    st.markdown("**Risk Level**")
    st.caption("Filters the Security Alerts section.")
    risk_level_filter = st.radio(
        label="Risk Level",
        options=["All", "Medium", "High"],
        index=0,
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.caption(
        "📌 Charts and metric cards always reflect the **full dataset** "
        "and are not affected by these filters."
    )
    st.markdown("---")
    st.caption(
        "🎓 **CyberShield** is an educational project.\n\n"
        "All data is simulated. No real systems are involved."
    )

# ===========================================================================
# Apply Filters
# ===========================================================================
filtered_df = (
    df.copy() if login_result_filter == "All"
    else df[df["Status"] == login_result_filter].copy()
)

filtered_alerts = (
    suspicious_ips.copy() if risk_level_filter == "All"
    else suspicious_ips[suspicious_ips["Risk Level"] == risk_level_filter].copy()
)

# ===========================================================================
# MAIN LAYOUT
# ===========================================================================

# ---------------------------------------------------------------------------
# 1. Header
# ---------------------------------------------------------------------------
st.title("🛡️ CyberShield")
st.markdown(
    "**Rule-Based Suspicious Login Detection and Security Monitoring Dashboard**"
)
st.markdown(
    "Analyzes simulated login activity, detects suspicious IP addresses based on "
    "repeated failed login attempts, assigns risk levels, and displays security analytics."
)

st.info(
    "🎓 **Educational Project** — IBM SkillsBuild Cyber Security 2026 (BharatCares)  \n"
    "All data is entirely simulated. This dashboard does not connect to any real system, "
    "database, or external API.",
    icon=None,
)

st.markdown("---")

# ---------------------------------------------------------------------------
# 2. Overview — Metric Cards
# ---------------------------------------------------------------------------
st.subheader("📊 Overview")
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(label="Total Logins", value=total_logins)
with col2:
    st.metric(label="Successful Logins", value=successful_logins)
with col3:
    st.metric(label="Failed Logins", value=failed_logins)
with col4:
    st.metric(label="Suspicious IPs Detected", value=suspicious_activities)

st.markdown("---")

# ---------------------------------------------------------------------------
# 3. Security Analytics — Charts
# ---------------------------------------------------------------------------
st.subheader("📈 Security Analytics")

chart_col1, chart_col2 = st.columns(2)

# Chart 1 — Login Outcome Summary
with chart_col1:
    st.markdown("**Login Outcome Summary**")
    st.caption("Successful vs. failed login attempts across all records.")

    outcome_data = pd.DataFrame({
        "Login Result": ["Successful", "Failed"],
        "Count":        [successful_logins, failed_logins],
    }).set_index("Login Result")

    st.bar_chart(outcome_data, color=["#58a6ff"], use_container_width=True, height=300)

# Chart 2 — Failed Login Attempts per IP Address
with chart_col2:
    st.markdown("**Failed Login Attempts per IP Address**")
    st.caption(
        f"IPs at or above the threshold of {FAILED_THRESHOLD} failed attempts are flagged "
        "in Security Alerts. Taller bars = higher concern."
    )

    all_ip_fails = (
        df[df["Status"] == "Failed"]
        .groupby("IP Address")
        .size()
        .reset_index(name="Failed Attempts")
        .sort_values("Failed Attempts", ascending=False)
        .set_index("IP Address")
    )

    st.bar_chart(all_ip_fails, color=["#da3633"], use_container_width=True, height=300)

    if not suspicious_ips.empty:
        flagged_list = ", ".join(suspicious_ips["IP Address"].tolist())
        st.caption(f"🔴 Currently flagged IPs: **{flagged_list}**")
    else:
        st.caption(f"✅ No IPs have reached the threshold of {FAILED_THRESHOLD} failed attempts.")

st.markdown("---")

# ---------------------------------------------------------------------------
# 4. Security Alerts
# ---------------------------------------------------------------------------
st.subheader("🚨 Security Alerts")

if risk_level_filter != "All":
    st.markdown(
        f"*Showing **{risk_level_filter} Risk** alerts only. "
        f"Select **All** in the sidebar to see all flagged IPs.*"
    )

# Disclaimer — required for all presentations
st.warning(
    "⚠️ **Important Disclaimer:** Suspicious login patterns flagged below do **not** "
    "automatically prove that a cyberattack has occurred. "
    "Alerts are generated by a simple rule: an IP address with **5 or more failed login "
    "attempts** is classified as suspicious. "
    "Every alert requires further human investigation before any conclusion is drawn. "
    "This is a simulated educational project — no real systems are involved.",
)

if filtered_alerts.empty:
    if suspicious_ips.empty:
        st.success("✅ No suspicious IP addresses detected in the current dataset.")
    else:
        st.info(
            f"No alerts match the **{risk_level_filter}** risk filter. "
            "Select **All** in the sidebar to view all flagged IPs."
        )
else:
    st.markdown(
        f"**{len(filtered_alerts)} of {len(suspicious_ips)} flagged IP address(es) shown** "
        f"— filter: {risk_level_filter} risk | threshold: ≥ {FAILED_THRESHOLD} failed attempts."
    )

    badge_class = {"High": "badge-high", "Medium": "badge-medium", "Low": "badge-low"}
    card_class  = {"High": "alert-high",  "Medium": "alert-medium",  "Low": "alert-low"}
    risk_icon   = {"High": "🔴",          "Medium": "🟡",            "Low": "🟢"}

    for _, row in filtered_alerts.iterrows():
        risk = row["Risk Level"]
        st.markdown(
            f"""
            <div class="alert-card {card_class[risk]}">
                <strong>🌐 IP Address:</strong> {row["IP Address"]}
                &nbsp;&nbsp;
                <span class="badge {badge_class[risk]}">{risk_icon[risk]} {risk} Risk</span>
                <br><br>
                <strong>👤 Username(s) involved:</strong> {row["usernames_involved"]}<br>
                <strong>❌ Failed attempts:</strong> {row["failed_attempts"]}<br>
                <strong>📋 Reason:</strong> {row["Reason"]}
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("---")

# ---------------------------------------------------------------------------
# 5. Login Activity Log
# ---------------------------------------------------------------------------
st.subheader("📋 Login Activity Log")

if login_result_filter != "All":
    st.markdown(
        f"*Showing **{login_result_filter}** records only — "
        f"{len(filtered_df)} of {total_logins} total rows.*"
    )
else:
    st.markdown(f"*Showing all {total_logins} records.*")


def highlight_status(val: str) -> str:
    """Colour-code Status cells. Valid values: Success (green) | Failed (red)."""
    colours = {"Success": "#238636", "Failed": "#da3633"}
    colour = colours.get(val, "transparent")
    return f"background-color: {colour}; color: white; border-radius: 4px; padding: 2px 6px;"


styled_df = filtered_df.style.applymap(highlight_status, subset=["Status"])
st.dataframe(styled_df, use_container_width=True, height=420)

st.markdown("---")

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown(
    "<p style='text-align:center; color:#8b949e; font-size:0.8rem;'>"
    "CyberShield v1.4 &nbsp;·&nbsp; "
    "IBM SkillsBuild Cyber Security 2026 &nbsp;·&nbsp; "
    "Kumari Shambhavi &nbsp;·&nbsp; "
    "Simulated data only — no real users or systems are represented."
    "</p>",
    unsafe_allow_html=True,
)
