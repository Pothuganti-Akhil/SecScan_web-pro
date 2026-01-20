import streamlit as st
import subprocess
from fpdf import FPDF
import csv
from datetime import datetime
import os
import pandas as pd
import ssl
import socket
import altair as alt
from urllib.parse import urlparse
import re

# ----------------- CONFIG -----------------
APP_NAME = "SecScan Web Pro"
APP_ICON = "🛡️"

# Set to True for GitHub/Streamlit Cloud deployment
# Set to False for Local/Linux full-power mode (Nmap + WhatWeb enabled)
CLOUD_MODE = True

st.set_page_config(
    page_title=APP_NAME,
    page_icon=APP_ICON,
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------- CYBER UI THEME -----------------
st.markdown("""
<style>
body, .stApp {
    background: linear-gradient(135deg, #020024, #0a0a3c, #001f3f);
}

.metric-card {
    background: rgba(0,0,0,0.65);
    padding: 20px;
    border-radius: 15px;
    text-align: center;
    box-shadow: 0px 0px 15px rgba(0,255,255,0.6);
    color: #e0ffff;
    transition: 0.3s;
}

.metric-card:hover {
    transform: scale(1.05);
    box-shadow: 0px 0px 25px rgba(0,255,255,1);
}

.title-glow {
    font-size: 34px;
    color: #00ffff;
    text-shadow: 0px 0px 15px #00ffff;
    font-weight: bold;
}

.sub-glow {
    color: #7fffd4;
    text-shadow: 0px 0px 8px #7fffd4;
}

.section-box {
    background: rgba(0,0,0,0.55);
    padding: 15px;
    border-radius: 12px;
    box-shadow: 0px 0px 12px rgba(0,0,0,0.8);
}
</style>
""", unsafe_allow_html=True)

# ----------------- STORAGE -----------------
HISTORY_FILE = "scan_history.csv"
COLUMNS = ["Time", "URL", "Score", "Risk Level", "SSL Status"]

# Ensure file exists
if not os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(COLUMNS)

# ----------------- HELPERS -----------------
def safe_filename(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name)

def get_domain_from_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.netloc

def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "❌ Command timed out."
    except Exception as e:
        return f"❌ Error: {str(e)}"

def check_ssl_expiry(domain):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.now()).days
                return True, days_left
    except:
        return False, 0

def parse_nmap_to_df(nmap_output):
    lines = nmap_output.split('\n')
    data = []
    for line in lines:
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port = parts[0]
            state = parts[1]
            service = parts[2] if len(parts) > 2 else "Unknown"
            data.append({"Port": port, "State": state, "Service": service})
    return pd.DataFrame(data)

def load_history_safe():
    if not os.path.exists(HISTORY_FILE):
        return pd.DataFrame(columns=COLUMNS)

    try:
        df = pd.read_csv(HISTORY_FILE)

        for col in COLUMNS:
            if col not in df.columns:
                df[col] = "Unknown"

        df = df[COLUMNS]
        df.to_csv(HISTORY_FILE, index=False)
        return df

    except Exception:
        backup = HISTORY_FILE + ".bak"
        try:
            os.rename(HISTORY_FILE, backup)
        except:
            pass

        with open(HISTORY_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(COLUMNS)

        return pd.DataFrame(columns=COLUMNS)

# ----------------- SIDEBAR -----------------
with st.sidebar:
    st.markdown(f"<div class='title-glow'>{APP_ICON} {APP_NAME}</div>", unsafe_allow_html=True)
    st.caption("v3.0 – Cloud + Local Edition")

    selected_page = st.radio(
        "Navigation",
        ["🚀 New Scan", "📊 Analytics & History", "ℹ️ About"]
    )

    st.divider()

    if st.button("🗑️ Clear Scan History"):
        try:
            if os.path.exists(HISTORY_FILE):
                os.remove(HISTORY_FILE)
            with open(HISTORY_FILE, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(COLUMNS)
            st.toast("History cleared!", icon="✅")
            st.rerun()
        except Exception as e:
            st.error(str(e))

    st.divider()
    st.subheader("🛠️ System Check")

    tools = {
        "Curl": "curl --version"
    }

    if not CLOUD_MODE:
        tools["Nmap"] = "nmap --version"
        tools["WhatWeb"] = "whatweb --version"

    for tool, cmd in tools.items():
        res = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            st.success(f"{tool} Ready")
        else:
            st.error(f"{tool} Missing")

    if CLOUD_MODE:
        st.info("☁️ Cloud Mode Active\nNmap & WhatWeb disabled")

# ----------------- NEW SCAN -----------------
if selected_page == "🚀 New Scan":
    st.markdown("<div class='title-glow'>🌐 Website Security Scanner</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-glow'>Automated Cyber Risk Assessment Platform</div>", unsafe_allow_html=True)

    col1, col2 = st.columns([3, 1])
    with col1:
        target_url = st.text_input("Target Website", placeholder="example.com")
    with col2:
        scan_mode = st.selectbox("Scan Mode", ["Quick", "Deep"])

    if st.button("🛡️ Launch Scan", use_container_width=True):
        if not target_url:
            st.error("Please enter a website URL")
        else:
            domain = get_domain_from_url(target_url)

            with st.status("Executing Security Modules...", expanded=True):
                st.write("🔒 Checking SSL...")
                ssl_valid, ssl_days = check_ssl_expiry(domain)

                st.write("📡 Fetching Headers...")
                headers_raw = run_cmd(f"curl -I -L --max-time 10 {target_url}")

                if CLOUD_MODE:
                    st.write("🔌 Nmap disabled (Cloud Mode)")
                    nmap_raw = "⚠️ Nmap scanning is disabled in cloud deployment."
                else:
                    st.write("🔌 Running Nmap...")
                    nmap_flag = "-F" if scan_mode == "Quick" else "-sV"
                    nmap_raw = run_cmd(f"nmap {nmap_flag} {domain}")

                if CLOUD_MODE:
                    st.write("🏗️ WhatWeb disabled (Cloud Mode)")
                    tech_raw = "⚠️ WhatWeb technology detection is disabled in cloud deployment."
                else:
                    st.write("🏗️ Running WhatWeb...")
                    tech_raw = run_cmd(f"whatweb {target_url}")

            # ----------------- SCORING -----------------
            score = 100
            issues = []
            recs = []

            if not ssl_valid:
                score -= 30
                issues.append("SSL Certificate Invalid")
                recs.append("Install a valid SSL certificate (Let's Encrypt recommended).")
            elif ssl_days < 30:
                score -= 10
                issues.append(f"SSL expires soon ({ssl_days} days left)")
                recs.append("Renew SSL certificate early.")

            headers_lower = headers_raw.lower()
            sec_headers = {
                "content-security-policy": "Add CSP to mitigate XSS",
                "x-frame-options": "Prevent clickjacking",
                "strict-transport-security": "Force HTTPS"
            }

            for h, msg in sec_headers.items():
                if h not in headers_lower:
                    score -= 10
                    issues.append(f"Missing {h}")
                    recs.append(msg)

            score = max(0, score)

            if score >= 85:
                risk = "Low"
            elif score >= 60:
                risk = "Medium"
            else:
                risk = "High"

            # ----------------- DASHBOARD -----------------
            st.divider()
            c1, c2, c3, c4 = st.columns(4)

            with c1:
                st.markdown(f"<div class='metric-card'>🔐<br><b>Score</b><br>{score}/100</div>", unsafe_allow_html=True)
            with c2:
                st.markdown(f"<div class='metric-card'>⚠️<br><b>Risk</b><br>{risk}</div>", unsafe_allow_html=True)
            with c3:
                st.markdown(f"<div class='metric-card'>🔒<br><b>SSL</b><br>{'Valid' if ssl_valid else 'Invalid'}</div>", unsafe_allow_html=True)
            with c4:
                st.markdown(f"<div class='metric-card'>⚙️<br><b>Mode</b><br>{scan_mode}</div>", unsafe_allow_html=True)

            tab1, tab2, tab3, tab4 = st.tabs(["📢 Findings", "🔌 Open Ports", "📝 Raw Output", "📄 PDF Report"])

            with tab1:
                st.markdown("<div class='section-box'>", unsafe_allow_html=True)
                st.subheader("⚠️ Issues")
                if issues:
                    for i in issues:
                        st.error(i)
                else:
                    st.success("No major risks found")

                st.subheader("💡 Recommendations")
                for r in recs:
                    st.info(r)
                st.markdown("</div>", unsafe_allow_html=True)

            with tab2:
                if CLOUD_MODE:
                    st.info("Open ports unavailable in Cloud Mode.")
                else:
                    df_ports = parse_nmap_to_df(nmap_raw)
                    if not df_ports.empty:
                        st.dataframe(df_ports, use_container_width=True)
                    else:
                        st.info("No open ports detected")

            with tab3:
                st.text_area("Headers Output", headers_raw, height=150)
                st.text_area("Nmap Output", nmap_raw, height=150)
                st.text_area("WhatWeb Output", tech_raw, height=150)

            with tab4:
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", "B", 16)
                pdf.cell(0, 10, f"{APP_NAME} - Security Report", ln=True, align="C")
                pdf.set_font("Arial", size=12)
                pdf.multi_cell(0, 8, f"""
Target: {target_url}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Score: {score}/100
Risk Level: {risk}

Issues:
{chr(10).join(issues) if issues else 'None'}

Recommendations:
{chr(10).join(recs) if recs else 'No actions required'}
""")

                pdf_name = f"report_{safe_filename(domain)}.pdf"
                pdf.output(pdf_name)

                with open(pdf_name, "rb") as f:
                    st.download_button("⬇️ Download PDF Report", f, pdf_name)

            # ----------------- SAVE HISTORY -----------------
            df_hist = load_history_safe()
            new_row = pd.DataFrame([{
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "URL": target_url,
                "Score": score,
                "Risk Level": risk,
                "SSL Status": "Valid" if ssl_valid else "Invalid"
            }])

            df_hist = pd.concat([df_hist, new_row], ignore_index=True)
            df_hist.to_csv(HISTORY_FILE, index=False)

# ----------------- HISTORY -----------------
elif selected_page == "📊 Analytics & History":
    st.markdown("<div class='title-glow'>📊 Security Analytics</div>", unsafe_allow_html=True)

    df = load_history_safe()

    if df.empty:
        st.info("No scans yet. Run a scan to see analytics.")
    else:
        df["Score"] = pd.to_numeric(df["Score"], errors="coerce").fillna(0)

        k1, k2, k3 = st.columns(3)
        k1.metric("Total Scans", len(df))
        k2.metric("Average Score", f"{df['Score'].mean():.1f}")
        k3.metric("Last Scan", df.iloc[-1]["Time"])

        st.divider()

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Risk Distribution")
            risk_counts = df["Risk Level"].value_counts().reset_index()
            risk_counts.columns = ["Risk", "Count"]

            chart = alt.Chart(risk_counts).mark_arc(innerRadius=50).encode(
                theta="Count",
                color=alt.Color(
                    "Risk",
                    scale=alt.Scale(
                        domain=["Low", "Medium", "High"],
                        range=["#00ff99", "#ffaa00", "#ff0033"]
                    )
                )
            )
            st.altair_chart(chart, use_container_width=True)

        with col2:
            st.subheader("Score Trend")
            df["Index"] = range(len(df))
            line = alt.Chart(df).mark_line(point=True).encode(
                x="Index",
                y="Score"
            )
            st.altair_chart(line, use_container_width=True)

        st.dataframe(df.sort_index(ascending=False), use_container_width=True)

# ----------------- ABOUT -----------------
elif selected_page == "ℹ️ About":
    st.markdown(f"<div class='title-glow'>ℹ️ About {APP_NAME}</div>", unsafe_allow_html=True)
    st.markdown("""
    **SecScan Web Pro** is a real-world, SOC-style web security assessment platform.

    🔐 **Core Modules**
    - SSL Certificate Validation & Expiry Tracking
    - HTTP Security Header Analysis
    - Nmap Port & Service Scanning (Local Mode)
    - Technology Fingerprinting (WhatWeb – Local Mode)
    - Risk Scoring Engine
    - PDF Security Report Generator
    - Analytics Dashboard

    ☁️ **Cloud Mode**
    Public demo mode disables system-level tools (Nmap & WhatWeb) for security and hosting compatibility.

    ⚠️ **Ethical Use Policy**
    Only scan websites you own or have explicit permission to test.
    """)
