
import json
import time
import os
import shutil
import streamlit as st
from pathlib import Path
from datetime import datetime
import pandas as pd

# Title and Config
st.set_page_config(page_title="🛡️ SecureAgent Live Dashboard", layout="wide", initial_sidebar_state="expanded")

# Paths
BASE_DIR = Path(__file__).parent.resolve()
DASHBOARD_DIR = BASE_DIR / "dashboard"
LOG_FILE = DASHBOARD_DIR / "security_events.jsonl"
SCREENSHOTS_DIR = DASHBOARD_DIR / "screenshots"

# Initialize Session State
if "confirm_delete" not in st.session_state:
    st.session_state.confirm_delete = False

# Sidebar
st.sidebar.title("🛡️ Zero-Trust Security")
page = st.sidebar.radio("Navigation", ["🔴 Live Feed", "📊 Risk Analysis", "🧠 XAI Explanations"])

st.sidebar.markdown("---")
st.sidebar.header("Monitor Controls")

if LOG_FILE.exists():
    st.sidebar.caption(f"✅ Log file active")
else:
    st.sidebar.caption(f"❌ Log file missing")

auto_refresh = st.sidebar.checkbox("Auto-Refresh (2s)", value=True)

st.sidebar.markdown("---")
st.sidebar.subheader("🚫 Danger Zone")

if st.sidebar.button("⚠️ Clear Logs & Evidence"):
    st.session_state.confirm_delete = True

if st.session_state.confirm_delete:
    st.sidebar.warning("Do you really wanna clear logs and delete screenshots?")
    col_confirm1, col_confirm2 = st.sidebar.columns(2)
    if col_confirm1.button("Yes, Delete"):
        if LOG_FILE.exists():
            os.remove(LOG_FILE)
        if SCREENSHOTS_DIR.exists():
            try:
                shutil.rmtree(SCREENSHOTS_DIR)
                os.makedirs(SCREENSHOTS_DIR)
            except Exception as e:
                st.sidebar.error(f"Error deleting screenshots: {e}")
        st.session_state.confirm_delete = False
        st.sidebar.success("All data wiped.")
        time.sleep(1)
        st.rerun()
    if col_confirm2.button("Cancel"):
        st.session_state.confirm_delete = False
        st.rerun()

# Load Data
events = []
if LOG_FILE.exists():
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))
    except Exception as e:
        st.error(f"Error reading logs: {e}")

# Helper to format timestamp
def get_formatted_time(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return ""

# Common Metrics
total_events = len(events)
injections_blocked = sum(1 for e in events if e.get('event_type') == 'INJECTION_ATTEMPT')
critical_threats = sum(1 for e in events if e.get('risk_level') == 'CRITICAL')
hostile_domains = len(set(e.get('url') for e in events if e.get('risk_level') in ['HIGH', 'CRITICAL']))
avg_risk = sum(e.get('risk_score', 0) for e in events) / max(total_events, 1)

# --- PAGE: LIVE FEED ---
if page == "🔴 Live Feed":
    st.title("🛡️ Real-time Security Feed")

    # Metrics Row
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Events", total_events)
    col2.metric("Injections Blocked", injections_blocked, delta_color="normal")
    col3.metric("Critical Threats", critical_threats, delta_color="inverse")
    col4.metric("Hostile Domains", hostile_domains)
    col5.metric("Avg Risk Score", f"{avg_risk:.0f}/100")

    st.divider()

    # Display Events (Latest First)
    for event in reversed(events):
        # Skip risk assessment events in live feed (too noisy)
        if event.get('event_type') == 'RISK_ASSESSMENT' and event.get('risk_level') == 'LOW':
            continue

        color = "gray"
        lvl = event.get('risk_level', 'SAFE')
        if lvl == 'CRITICAL': color = "red"
        elif lvl == 'HIGH': color = "orange"
        elif lvl == 'MEDIUM': color = "yellow"
        elif lvl == 'SAFE': color = "green"

        risk_score = event.get('risk_score', 0)

        with st.container(border=True):
            cols = st.columns([2, 2, 5, 1, 2])

            timestamp_val = event.get('timestamp')
            display_time = get_formatted_time(timestamp_val) if timestamp_val else event.get('time_str', 'N/A')

            cols[0].caption(f"📅 {display_time}")
            cols[1].markdown(f"**:{color}[{event.get('event_type')}]**")
            cols[2].write(f"{event.get('details')} \n\n 🔗 `{event.get('url', 'N/A')}`")
            
            # Risk Score Badge
            if risk_score >= 71:
                cols[3].markdown(f"**:red[{risk_score}]**")
            elif risk_score >= 31:
                cols[3].markdown(f"**:orange[{risk_score}]**")
            else:
                cols[3].markdown(f"**:green[{risk_score}]**")
            
            cols[4].caption(f"Action: **{event.get('action')}**")

            # XAI Explanation
            explanation = event.get('explanation')
            if explanation:
                st.info(f"🧠 **AI Explanation:** {explanation}")

            if event.get('screenshot'):
                try:
                    raw_path = event['screenshot']
                    filename = raw_path.replace('\\', '/').split('/')[-1]
                    local_path = SCREENSHOTS_DIR / filename
                    if local_path.exists():
                        st.image(str(local_path), caption="Evidence Snapshot", width=400)
                except Exception:
                    pass

# --- PAGE: RISK ANALYSIS ---
elif page == "📊 Risk Analysis":
    st.title("📊 Risk Score Analysis")

    if total_events == 0:
        st.info("No data available yet. Run the agent to generate traffic.")
    else:
        df = pd.DataFrame(events)
        if 'timestamp' in df.columns:
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')

        # Stats Overview
        st.header("📈 Activity Overview")
        unique_sites = df['url'].nunique() if 'url' in df.columns else 0
        malicious_count = df[df['risk_level'].isin(['HIGH', 'CRITICAL'])]['url'].nunique() if 'risk_level' in df.columns else 0
        blocked_count = df[df['action'].isin(['BLOCKED', 'SANITIZED', 'WARNED', 'BLOCK_AND_ESCALATE'])]['url'].count() if 'action' in df.columns else 0

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("🌍 Unique Sites", unique_sites)
        m2.metric("💀 Malicious Domains", malicious_count, delta_color="inverse")
        m3.metric("🛡️ Interventions", blocked_count)
        m4.metric("📊 Avg Risk", f"{avg_risk:.0f}/100")

        st.divider()

        # Risk Score Timeline
        g1, g2 = st.columns(2)
        with g1:
            st.subheader("Risk Score Timeline")
            if 'risk_score' in df.columns and 'datetime' in df.columns:
                risk_df = df[df['risk_score'] > 0][['datetime', 'risk_score']].set_index('datetime')
                if not risk_df.empty:
                    st.line_chart(risk_df, color="#ff4b4b")
                else:
                    st.info("No risk scores yet.")

        with g2:
            st.subheader("Threat Severity Distribution")
            if 'risk_level' in df.columns:
                risk_counts = df['risk_level'].value_counts()
                st.bar_chart(risk_counts, color="#ff4b4b")

        st.divider()

        # Risk Score Distribution
        st.subheader("Risk Score Distribution")
        if 'risk_score' in df.columns:
            risk_scores = df[df['risk_score'] > 0]['risk_score']
            if not risk_scores.empty:
                col_low, col_med, col_high = st.columns(3)
                col_low.metric("🟢 Low (0-30)", len(risk_scores[risk_scores <= 30]))
                col_med.metric("🟡 Medium (31-70)", len(risk_scores[(risk_scores > 30) & (risk_scores <= 70)]))
                col_high.metric("🔴 High (71-100)", len(risk_scores[risk_scores > 70]))

        st.divider()

        # Event Types
        st.subheader("Event Types")
        if 'event_type' in df.columns:
            type_counts = df['event_type'].value_counts()
            st.bar_chart(type_counts, horizontal=True)

        st.divider()

        # Detailed Tables
        st.subheader("📝 Malicious Sites Identified")
        if 'risk_level' in df.columns and 'url' in df.columns:
            malicious_df = df[df['risk_level'].isin(['HIGH', 'CRITICAL'])][['datetime', 'url', 'risk_level', 'risk_score', 'details']].drop_duplicates(subset=['url'])
            if not malicious_df.empty:
                st.dataframe(malicious_df, use_container_width=True)
            else:
                st.success("No malicious sites detected.")

        st.subheader("🛡️ Blocked / Sanitized Actions")
        if 'action' in df.columns:
            blocked_df = df[df['action'].isin(['BLOCKED', 'SANITIZED', 'BLOCK_AND_ESCALATE'])][['datetime', 'event_type', 'url', 'risk_score', 'details']]
            if not blocked_df.empty:
                st.dataframe(blocked_df, use_container_width=True)
            else:
                st.info("No active blocking recorded yet.")

# --- PAGE: XAI EXPLANATIONS ---
elif page == "🧠 XAI Explanations":
    st.title("🧠 Explainable AI — Security Decisions")
    st.caption("LLM-generated explanations for every blocked or flagged action")

    explanation_events = [e for e in events if e.get('explanation')]
    
    if not explanation_events:
        st.info("No XAI explanations yet. Explanations are generated when actions are blocked.")
    else:
        for event in reversed(explanation_events):
            risk_score = event.get('risk_score', 0)
            
            with st.container(border=True):
                cols = st.columns([1, 5])
                
                # Risk gauge
                if risk_score >= 71:
                    cols[0].markdown(f"### :red[{risk_score}/100]")
                    cols[0].caption("🔴 HIGH RISK")
                elif risk_score >= 31:
                    cols[0].markdown(f"### :orange[{risk_score}/100]")
                    cols[0].caption("🟡 MEDIUM")
                else:
                    cols[0].markdown(f"### :green[{risk_score}/100]")
                    cols[0].caption("🟢 LOW")

                timestamp_val = event.get('timestamp')
                display_time = get_formatted_time(timestamp_val) if timestamp_val else ''
                
                cols[1].markdown(f"**{event.get('event_type', 'UNKNOWN')}** — {display_time}")
                cols[1].markdown(f"> {event.get('explanation', 'No explanation available.')}")
                cols[1].caption(f"🔗 {event.get('url', 'N/A')} | Action: {event.get('action', 'N/A')}")

                if event.get('screenshot'):
                    try:
                        raw_path = event['screenshot']
                        filename = raw_path.replace('\\', '/').split('/')[-1]
                        local_path = SCREENSHOTS_DIR / filename
                        if local_path.exists():
                            st.image(str(local_path), caption="Evidence Snapshot", width=400)
                    except Exception:
                        pass


if auto_refresh:
    time.sleep(2)
    st.rerun()
