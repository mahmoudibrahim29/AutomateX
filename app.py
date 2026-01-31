import os
import json
import time
from datetime import datetime

import pandas as pd
import streamlit as st
import altair as alt
from dotenv import load_dotenv

from utils.ioc_detect import detect_ioc_type
from utils.normalize import vt_url_id
from utils.defang import defang_ioc
from utils.scoring import score_from_vt
from utils.cache import Cache
from providers.virustotal import VirusTotalClient


# ----------------------------
# Tab icon (favicon) + Page setup
# ----------------------------
page_icon = "🛡️"
if os.path.exists("assets/favicon.png"):
    page_icon = "assets/favicon.png"

st.set_page_config(
    page_title="AutomateX Threat Intel Platform",
    page_icon=page_icon,
    layout="wide",
    initial_sidebar_state="expanded",
)

# ----------------------------
# Neon theme (CSS only) + BIGGER TABLE FIX
# ----------------------------
st.markdown(
    """
    <style>
    .stApp {
        background: radial-gradient(1200px 600px at 50% 0%, rgba(0,255,255,0.12), transparent 60%),
                    radial-gradient(900px 500px at 20% 30%, rgba(77,163,255,0.10), transparent 60%),
                    radial-gradient(900px 500px at 85% 45%, rgba(0,255,170,0.08), transparent 60%),
                    linear-gradient(180deg, #050a12 0%, #060b14 100%);
        color: #e8f1ff;
    }
    header {visibility: hidden;}
    footer {visibility: hidden;}
    .block-container {padding-top: 1.0rem; padding-bottom: 2rem; max-width: 1300px;}

    section[data-testid="stSidebar"] {
        background: rgba(7, 14, 24, 0.85) !important;
        border-right: 1px solid rgba(90, 220, 255, 0.14) !important;
        box-shadow: 0 0 22px rgba(77,163,255,0.08);
    }

    .stTextArea textarea,
    .stTextInput input,
    .stSelectbox div[data-baseweb="select"],
    .stNumberInput input,
    .stMultiSelect div[data-baseweb="select"],
    .stFileUploader {
        background: rgba(10, 18, 30, 0.72) !important;
        border: 1px solid rgba(90, 220, 255, 0.18) !important;
        border-radius: 14px !important;
        color: #e8f1ff !important;
        box-shadow: 0 0 18px rgba(77,163,255,0.06);
    }

    button[data-baseweb="tab"] { color: rgba(210, 232, 255, 0.92) !important; }
    button[data-baseweb="tab"][aria-selected="true"] {
        border-bottom: 2px solid rgba(87,240,255,0.85) !important;
        text-shadow: 0 0 16px rgba(87,240,255,0.14);
    }

    div.stButton > button {
        border-radius: 14px !important;
        border: 1px solid rgba(87,240,255,0.38) !important;
        background: linear-gradient(90deg, rgba(0,255,255,0.10), rgba(77,163,255,0.10)) !important;
        color: #dffbff !important;
        font-weight: 900 !important;
        padding: 0.85rem 1rem !important;
        transition: all .15s ease !important;
        width: 100% !important;
        box-shadow: 0 0 18px rgba(87,240,255,0.10) !important;
    }
    div.stButton > button:hover {
        transform: translateY(-1px);
        border: 1px solid rgba(87,240,255,0.75) !important;
        box-shadow: 0 0 26px rgba(87,240,255,0.16) !important;
    }

    .stDataFrame, .stTable {
        border: 1px solid rgba(90, 220, 255, 0.14);
        border-radius: 14px;
        overflow: hidden;
        box-shadow: 0 0 24px rgba(77,163,255,0.08);
    }

    div[data-testid="stMetric"] {
        background: rgba(10, 18, 30, 0.55);
        border: 1px solid rgba(90, 220, 255, 0.14);
        border-radius: 16px;
        padding: 10px 14px;
        box-shadow: 0 0 18px rgba(77,163,255,0.06);
    }

    label { color: rgba(210, 232, 255, 0.92) !important; font-weight: 650 !important; }

    hr {
        border: none;
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(87,240,255,0.35), transparent);
    }

    .ax-detail-card{
        background: rgba(10, 18, 30, 0.72);
        border: 1px solid rgba(90, 220, 255, 0.18);
        border-radius: 16px;
        padding: 14px 16px;
        box-shadow: 0 0 22px rgba(77,163,255,0.08);
        height: 100%;
    }
    .ax-detail-title{
        font-weight: 900;
        font-size: 16px;
        color: rgba(223, 251, 255, 0.95);
        margin-bottom: 8px;
    }

    .ax-topcard{
        background: rgba(10, 18, 30, 0.72);
        border: 1px solid rgba(90, 220, 255, 0.22);
        border-radius: 18px;
        padding: 14px 16px;
        box-shadow: 0 0 24px rgba(255, 0, 80, 0.08);
        height: 100%;
    }

    /* ===== Bigger dataframe text + rows ===== */
    div[data-testid="stDataFrame"] table {
        font-size: 15px !important;
    }
    div[data-testid="stDataFrame"] td {
        padding-top: 10px !important;
        padding-bottom: 10px !important;
        white-space: nowrap !important;
    }
    div[data-testid="stDataFrame"] th {
        font-size: 15px !important;
        white-space: nowrap !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ----------------------------
# Env + VT key
# ----------------------------
load_dotenv()
VT_KEY = (os.getenv("VT_API_KEY") or "").strip()

# ----------------------------
# Helpers
# ----------------------------
def badge(verdict: str) -> str:
    v = (verdict or "").lower()
    if v == "malicious":
        return "🟥 Malicious"
    if v == "suspicious":
        return "🟧 Suspicious"
    if v == "clean":
        return "🟩 Clean"
    if v == "error":
        return "⬛ Error"
    return "⬜ Unknown"

def score_color(score: int) -> str:
    if score >= 70:
        return "background-color: rgba(255, 0, 80, 0.15);"
    if score >= 30:
        return "background-color: rgba(255, 170, 0, 0.15);"
    return "background-color: rgba(0, 255, 170, 0.12);"

def verdict_color(verdict: str) -> str:
    v = (verdict or "").lower()
    if "malicious" in v:
        return "background-color: rgba(255, 0, 80, 0.15);"
    if "suspicious" in v:
        return "background-color: rgba(255, 170, 0, 0.15);"
    if "clean" in v:
        return "background-color: rgba(0, 255, 170, 0.12);"
    if "error" in v:
        return "background-color: rgba(120, 120, 120, 0.14);"
    return "background-color: rgba(200, 200, 200, 0.12);"

def vt_web_url(ioc: str, ioc_type: str) -> str:
    t = (ioc_type or "").lower()
    if t == "ip":
        return f"https://www.virustotal.com/gui/ip-address/{ioc}"
    if t == "domain":
        return f"https://www.virustotal.com/gui/domain/{ioc}"
    if t == "url":
        return f"https://www.virustotal.com/gui/url/{vt_url_id(ioc)}"
    if t in ("md5", "sha1", "sha256"):
        return f"https://www.virustotal.com/gui/file/{ioc}"
    return "https://www.virustotal.com/gui/home/search"

# ----------------------------
# MITRE ATT&CK (Suggested mapping)
# ----------------------------
def suggest_mitre(ioc_type: str, context: str) -> list[str]:
    """
    IOC alone does NOT confirm a technique.
    This is a suggested mapping based on context + IOC type.
    """
    t = (ioc_type or "").lower()
    c = (context or "").lower()

    if "phishing" in c:
        return ["T1566 (Phishing)", "T1566.002 (Spearphishing Link)"]
    if "command" in c or "c2" in c:
        return ["T1071 (Application Layer Protocol)", "T1095 (Non-Application Layer Protocol)"]
    if "malware" in c or "delivery" in c:
        return ["T1105 (Ingress Tool Transfer)", "T1204 (User Execution)"]
    if "scanning" in c or "recon" in c:
        return ["T1595 (Active Scanning)", "T1590 (Gather Victim Network Information)"]

    # Auto type-based (conservative)
    if t in ["ip", "domain"]:
        return ["T1071 (Application Layer Protocol)"]
    if t == "url":
        return ["T1566.002 (Spearphishing Link)", "T1105 (Ingress Tool Transfer)"]
    if t in ["md5", "sha1", "sha256"]:
        return ["T1105 (Ingress Tool Transfer)", "T1204 (User Execution)"]

    return []

# ----------------------------
# Header
# ----------------------------
st.markdown(
    """
    <div style="text-align:center; margin-top:8px; margin-bottom:6px;">
        <div style="
            font-size:56px;
            font-weight:900;
            letter-spacing:1px;
            color:#57f0ff;
            text-shadow: 0 0 28px rgba(87,240,255,.25);
        ">
            AutomateX
        </div>
    </div>
    """,
    unsafe_allow_html=True
)
st.markdown(
    "<div style='text-align:center; font-size:22px; font-weight:700; color:#cfe6ff; opacity:.92; margin-bottom:10px;'>Threat Intelligence Platform</div>",
    unsafe_allow_html=True
)
st.markdown(
    "<div style='text-align:center; font-size:14px; opacity:.75; margin-bottom:16px;'>IOC Reputation • VirusTotal Intelligence • SOC Automation</div>",
    unsafe_allow_html=True
)
st.divider()

# ----------------------------
# Sidebar controls
# ----------------------------
with st.sidebar:
    st.header("⚙️ Settings")

    if not VT_KEY:
        st.error("VT_API_KEY not found in .env")
        st.stop()

    cache_ttl = st.number_input("Cache TTL (seconds)", min_value=60, max_value=604800, value=86400, step=60)
    show_defanged = st.toggle("Show defanged IOCs", value=True)
    max_iocs = st.number_input("Max IOCs per run", min_value=1, max_value=500, value=500, step=1)
    sleep_between = st.slider("Delay between checks (sec)", 0.0, 2.0, 0.2, 0.1)

    st.markdown("---")
    st.subheader("🧩 MITRE ATT&CK Mapping")
    mitre_context = st.selectbox(
        "Context for suggested techniques",
        ["Auto (type-based)", "Phishing", "Command & Control", "Malware Delivery", "Scanning / Recon"],
        index=0
    )
    st.caption("Suggested mapping based on context + IOC type (not confirmation).")

    st.markdown("---")
    st.caption("Tip: Keep delay > 0 to reduce rate-limit issues.")

vt = VirusTotalClient(VT_KEY)
cache = Cache("ioc_cache.db")

# ----------------------------
# Input area (Tabs)
# ----------------------------
tab1, tab2 = st.tabs(["✍️ Paste IOCs", "📄 Upload iocs.txt"])
iocs: list[str] = []

with tab1:
    ioc_text = st.text_area(
        "Paste IOCs (one per line). Lines starting with # are ignored.",
        height=200,
        placeholder="8.8.8.8\nexample.com\nhttps://example.com/login\n44d88612fea8a8f36de82e1278abb02f",
    )
    if ioc_text.strip():
        for line in ioc_text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            iocs.append(s)

with tab2:
    uploaded = st.file_uploader("Upload a .txt file (one IOC per line)", type=["txt"])
    if uploaded:
        content = uploaded.read().decode("utf-8", errors="ignore").splitlines()
        for line in content:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            iocs.append(s)

# de-dupe preserving order
seen = set()
iocs = [x for x in iocs if not (x in seen or seen.add(x))]

# limit
if len(iocs) > int(max_iocs):
    st.warning(f"Too many IOCs ({len(iocs)}). Limiting to {int(max_iocs)} for this run.")
    iocs = iocs[: int(max_iocs)]

colA, colB, colC = st.columns([1, 1, 2])
with colA:
    run_btn = st.button("🚀 Run Checks", use_container_width=True, disabled=(len(iocs) == 0))
with colB:
    clear_btn = st.button("🧹 Clear Results", use_container_width=True)
with colC:
    st.caption(f"Loaded IOCs: **{len(iocs)}** (max per run: {int(max_iocs)})")

# ----------------------------
# State
# ----------------------------
if "results" not in st.session_state or clear_btn:
    st.session_state["results"] = []
if "last_run" not in st.session_state:
    st.session_state["last_run"] = None

# ----------------------------
# VT fetch
# ----------------------------
def fetch_vt_stats(ioc: str, ioc_type: str) -> dict:
    if ioc_type == "ip":
        data = vt.lookup_ip(ioc)
    elif ioc_type == "domain":
        data = vt.lookup_domain(ioc)
    elif ioc_type == "url":
        data = vt.lookup_url(vt_url_id(ioc))
    elif ioc_type in ("md5", "sha1", "sha256"):
        data = vt.lookup_hash(ioc)
    else:
        raise ValueError("Unknown IOC type")
    return data["data"]["attributes"].get("last_analysis_stats", {})

# ----------------------------
# Main runner
# ----------------------------
if run_btn and iocs:
    results = []
    progress = st.progress(0)
    status = st.empty()

    start = time.time()
    cache_hits = 0

    for idx, ioc in enumerate(iocs, start=1):
        progress.progress(int((idx / max(len(iocs), 1)) * 100))
        status.info(f"Checking {idx}/{len(iocs)}: {ioc}")

        ioc_type = detect_ioc_type(ioc)
        ioc_display = defang_ioc(ioc) if show_defanged else ioc

        entry = {
            "ioc": ioc,
            "ioc_display": ioc_display,
            "type": ioc_type,
            "mitre": suggest_mitre(ioc_type, mitre_context),
            "verdict": "unknown",
            "score": 0,
            "vt_malicious": None,
            "vt_suspicious": None,
            "vt_harmless": None,
            "vt_undetected": None,
            "source": "live",
            "error": "",
            "checked_at": datetime.utcnow().isoformat() + "Z",
        }

        try:
            cached = cache.get(ioc, "virustotal", ttl_seconds=int(cache_ttl))
            if cached:
                vt_stats = cached.get("stats", {})
                cache_hits += 1
                entry["source"] = "cache"
            else:
                vt_stats = fetch_vt_stats(ioc, ioc_type)
                cache.set(ioc, "virustotal", {"stats": vt_stats})
                entry["source"] = "live"

            verdict_obj = score_from_vt(vt_stats)
            entry["verdict"] = verdict_obj.get("verdict", "unknown")
            entry["score"] = int(verdict_obj.get("score", 0))

            entry["vt_malicious"] = vt_stats.get("malicious")
            entry["vt_suspicious"] = vt_stats.get("suspicious")
            entry["vt_harmless"] = vt_stats.get("harmless")
            entry["vt_undetected"] = vt_stats.get("undetected")

        except Exception as e:
            entry["verdict"] = "error"
            entry["score"] = 0
            entry["error"] = str(e)

        results.append(entry)

        if sleep_between > 0:
            time.sleep(float(sleep_between))

    duration = round(time.time() - start, 2)
    st.session_state["results"] = results
    st.session_state["last_run"] = {"duration": duration, "cache_hits": cache_hits, "total": len(iocs)}

    status.success(f"Done. Checked {len(iocs)} IOC(s) in {duration}s | Cache hits: {cache_hits}")
    progress.empty()

# ----------------------------
# Results UI
# ----------------------------
results = st.session_state.get("results", [])
last_run = st.session_state.get("last_run")

if results:
    df = pd.DataFrame(results)

    # Safety if old session missing mitre
    if "mitre" not in df.columns:
        df["mitre"] = [[] for _ in range(len(df))]

    # KPIs
    clean_count = int((df["verdict"] == "clean").sum())
    susp_count = int((df["verdict"] == "suspicious").sum())
    mal_count = int((df["verdict"] == "malicious").sum())
    err_count = int((df["verdict"] == "error").sum())

    c1, c2, c3, c4, c5 = st.columns([1, 1, 1, 1, 2])
    c1.metric("🟩 Clean", clean_count)
    c2.metric("🟧 Suspicious", susp_count)
    c3.metric("🟥 Malicious", mal_count)
    c4.metric("⬛ Errors", err_count)
    if last_run:
        c5.metric("⏱️ Last run", f"{last_run['duration']}s", f"Cache hits: {last_run['cache_hits']}/{last_run['total']}")

    st.divider()

    # Filters
    f1, f2, f3 = st.columns([1, 1, 2])
    with f1:
        verdict_filter = st.multiselect(
            "Filter verdict",
            ["clean", "suspicious", "malicious", "error", "unknown"],
            default=["clean", "suspicious", "malicious", "error"],
        )
    with f2:
        type_filter = st.multiselect(
            "Filter type",
            sorted(df["type"].unique().tolist()),
            default=sorted(df["type"].unique().tolist()),
        )
    with f3:
        search = st.text_input("Search IOC (substring)", value="")

    filtered = df[df["verdict"].isin(verdict_filter) & df["type"].isin(type_filter)].copy()
    if search.strip():
        filtered = filtered[filtered["ioc"].str.contains(search.strip(), case=False, na=False)]

    filtered["Verdict"] = filtered["verdict"].apply(badge)
    filtered["MITRE (Suggested)"] = filtered["mitre"].apply(lambda x: ", ".join(x) if isinstance(x, list) else "")

    # ----------------------------
    # Priority Triage + colored charts
    # ----------------------------
    st.subheader("🧠 Priority Triage")

    left, right = st.columns([1.1, 1.9])

    with left:
        st.markdown('<div class="ax-topcard">', unsafe_allow_html=True)
        st.markdown("**Top 5 Most Malicious IOCs**")

        top5 = df.sort_values(["score"], ascending=False).head(5)[["ioc_display", "type", "verdict", "score"]].copy()
        if top5.empty:
            st.write("No data.")
        else:
            top5["verdict"] = top5["verdict"].apply(badge)
            st.table(top5.rename(columns={"ioc_display": "IOC", "type": "Type", "verdict": "Verdict", "score": "Score"}))

        st.markdown("</div>", unsafe_allow_html=True)

    verdict_order = ["malicious", "suspicious", "clean", "error", "unknown"]
    verdict_colors = {
        "malicious": "#ff0050",
        "suspicious": "#ffaa00",
        "clean": "#00ffaa",
        "error": "#9aa0a6",
        "unknown": "#6c8fb3",
    }

    with right:
        st.markdown("**Visual Summary**")

        verdict_df = filtered["verdict"].value_counts().reset_index()
        verdict_df.columns = ["verdict", "count"]

        chart_verdict = (
            alt.Chart(verdict_df)
            .mark_bar()
            .encode(
                x=alt.X("verdict:N", sort=verdict_order, axis=alt.Axis(labelAngle=0, title="Verdict")),
                y=alt.Y("count:Q", title="Count"),
                color=alt.Color(
                    "verdict:N",
                    scale=alt.Scale(domain=list(verdict_colors.keys()), range=list(verdict_colors.values())),
                    legend=None
                ),
                tooltip=["verdict", "count"]
            )
            .properties(height=240)
        )

        type_df = filtered["type"].value_counts().reset_index()
        type_df.columns = ["type", "count"]

        chart_type = (
            alt.Chart(type_df)
            .mark_bar()
            .encode(
                x=alt.X("type:N", axis=alt.Axis(labelAngle=0, title="IOC Type")),
                y=alt.Y("count:Q", title="Count"),
                color=alt.value("#57f0ff"),
                tooltip=["type", "count"]
            )
            .properties(height=240)
        )

        cX, cY = st.columns(2)
        with cX:
            st.altair_chart(chart_verdict, use_container_width=True)
        with cY:
            st.altair_chart(chart_type, use_container_width=True)

    st.divider()

    # ----------------------------
    # Results table (BIGGER + column widths)
    # ----------------------------
    st.subheader("📋 Results Table")

    show_cols = [
        "ioc_display", "type", "Verdict", "score",
        "MITRE (Suggested)",
        "vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected",
        "source", "error"
    ]

    filtered_view = filtered[show_cols].rename(
        columns={
            "ioc_display": "IOC",
            "type": "Type",
            "score": "Score",
            "source": "Source",
            "error": "Error",
            "vt_malicious": "VT Malicious",
            "vt_suspicious": "VT Suspicious",
            "vt_harmless": "VT Harmless",
            "vt_undetected": "VT Undetected",
        }
    )

    styled = filtered_view.style.applymap(
        lambda v: score_color(v) if isinstance(v, int) else "",
        subset=["Score"]
    ).applymap(
        lambda v: verdict_color(
            v.replace("🟥 ", "").replace("🟧 ", "").replace("🟩 ", "").replace("⬛ ", "").replace("⬜ ", "")
        ) if isinstance(v, str) else "",
        subset=["Verdict"]
    )

    st.dataframe(
        styled,
        use_container_width=True,
        height=560,
        column_config={
            "IOC": st.column_config.TextColumn(width="large"),
            "Type": st.column_config.TextColumn(width="small"),
            "Verdict": st.column_config.TextColumn(width="medium"),
            "Score": st.column_config.NumberColumn(width="small"),
            "MITRE (Suggested)": st.column_config.TextColumn(width="large"),
            "VT Malicious": st.column_config.NumberColumn(width="small"),
            "VT Suspicious": st.column_config.NumberColumn(width="small"),
            "VT Harmless": st.column_config.NumberColumn(width="small"),
            "VT Undetected": st.column_config.NumberColumn(width="small"),
            "Source": st.column_config.TextColumn(width="small"),
            "Error": st.column_config.TextColumn(width="large"),
        },
    )

    # ----------------------------
    # IOC Details + VT link + horizontal stats labels
    # ----------------------------
    st.subheader("🔍 IOC Details")

    pick_list = filtered["ioc"].tolist()
    pick = st.selectbox("Select an IOC to view details", pick_list)
    row = df[df["ioc"] == pick].iloc[0].to_dict()

    vt_link = vt_web_url(row.get("ioc", ""), row.get("type", ""))
    st.markdown(f'🔗 <a href="{vt_link}" target="_blank">Open this IOC in VirusTotal</a>', unsafe_allow_html=True)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Type", str(row.get("type", "")).upper())
    m2.metric("Verdict", badge(row.get("verdict", "")))
    m3.metric("Score", int(row.get("score", 0)))
    m4.metric("Source", str(row.get("source", "")).upper())

    st.write("")

    d1, d2 = st.columns(2)
    with d1:
        st.markdown('<div class="ax-detail-card">', unsafe_allow_html=True)
        st.markdown('<div class="ax-detail-title">Overview</div>', unsafe_allow_html=True)

        mitre_list = row.get("mitre", [])
        mitre_text = ", ".join(mitre_list) if isinstance(mitre_list, list) else ""

        overview_df = pd.DataFrame(
            [
                ["IOC", row.get("ioc_display", "")],
                ["Raw IOC", row.get("ioc", "")],
                ["Type", row.get("type", "")],
                ["Verdict", badge(row.get("verdict", ""))],
                ["Score", row.get("score", 0)],
                ["Source", row.get("source", "")],
                ["MITRE (Suggested)", mitre_text],
            ],
            columns=["Field", "Value"]
        )
        st.table(overview_df)

        if row.get("error"):
            st.error(row["error"])

        st.markdown("</div>", unsafe_allow_html=True)

    with d2:
        st.markdown('<div class="ax-detail-card">', unsafe_allow_html=True)
        st.markdown('<div class="ax-detail-title">VirusTotal last_analysis_stats</div>', unsafe_allow_html=True)

        vt_stats = {
            "malicious": int(row.get("vt_malicious") or 0),
            "suspicious": int(row.get("vt_suspicious") or 0),
            "harmless": int(row.get("vt_harmless") or 0),
            "undetected": int(row.get("vt_undetected") or 0),
        }

        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Malicious", vt_stats["malicious"])
        s2.metric("Suspicious", vt_stats["suspicious"])
        s3.metric("Harmless", vt_stats["harmless"])
        s4.metric("Undetected", vt_stats["undetected"])

        stats_df = pd.DataFrame({
            "category": ["malicious", "suspicious", "harmless", "undetected"],
            "count": [vt_stats["malicious"], vt_stats["suspicious"], vt_stats["harmless"], vt_stats["undetected"]],
        })

        color_map = {
            "malicious": "#ff0050",
            "suspicious": "#ffaa00",
            "harmless": "#00ffaa",
            "undetected": "#57f0ff",
        }

        chart_stats = (
            alt.Chart(stats_df)
            .mark_bar()
            .encode(
                x=alt.X("category:N", axis=alt.Axis(labelAngle=0, title="")),
                y=alt.Y("count:Q", title="Count"),
                color=alt.Color(
                    "category:N",
                    scale=alt.Scale(domain=list(color_map.keys()), range=list(color_map.values())),
                    legend=None
                ),
                tooltip=["category", "count"]
            )
            .properties(height=260)
        )

        st.altair_chart(chart_stats, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # ----------------------------
    # Timeline view (optional)
    # ----------------------------
    st.subheader("📊 Timeline (optional)")

    time_candidates = ["checked_at", "_time", "time", "timestamp", "datetime"]
    time_col = next((c for c in time_candidates if c in df.columns), None)

    if not time_col:
        st.info("No timestamp column found yet. When you add logs later, include a time field (e.g., _time or timestamp) and this timeline will auto-appear.")
    else:
        tmp = df.copy()
        tmp[time_col] = pd.to_datetime(tmp[time_col], errors="coerce", utc=True)
        tmp = tmp.dropna(subset=[time_col])

        if tmp.empty:
            st.info("Timestamp column exists but no valid timestamps to plot.")
        else:
            tmp["bucket"] = tmp[time_col].dt.floor("min")
            timeline = tmp.groupby(["bucket", "verdict"]).size().reset_index(name="count")

            chart_timeline = (
                alt.Chart(timeline)
                .mark_line(point=True)
                .encode(
                    x=alt.X("bucket:T", title="Time"),
                    y=alt.Y("count:Q", title="Count"),
                    color=alt.Color(
                        "verdict:N",
                        scale=alt.Scale(domain=list(verdict_colors.keys()), range=list(verdict_colors.values())),
                        title="Verdict"
                    ),
                    tooltip=["bucket:T", "verdict:N", "count:Q"]
                )
                .properties(height=320)
            )

            st.altair_chart(chart_timeline, use_container_width=True)

    # ----------------------------
    # Export (JSON only)
    # ----------------------------
    st.subheader("⬇️ Export")
    export_payload = df.to_dict(orient="records")
    st.download_button(
        "Download JSON",
        data=json.dumps(export_payload, indent=2),
        file_name="ioc_results.json",
        mime="application/json",
        use_container_width=True
    )

else:
    st.info("Paste IOCs or upload a file, then click **Run Checks**.")
