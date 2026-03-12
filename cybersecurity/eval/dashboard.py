"""
eval/dashboard.py — cybersecurity Executive Dashboard
Run: streamlit run eval/dashboard.py
"""

from __future__ import annotations
import json
import sys
from pathlib import Path

# Ensure project root is on sys.path regardless of where Streamlit is launched from
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st

from config import EVAL_RESULTS_DIR

st.set_page_config(
    page_title="cybersecurity SOC Dashboard",
    page_icon="[S]️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  /* Dark header bar */
  [data-testid="stHeader"] { background: #0d1117; }

  /* Sidebar */
  [data-testid="stSidebar"] { background: #161b22; }
  [data-testid="stSidebar"] * { color: #c9d1d9 !important; }

  /* Main background */
  .main .block-container { background: #0d1117; padding-top: 1.5rem; }

  /* Metric cards */
  [data-testid="stMetric"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 16px 20px;
  }
  [data-testid="stMetricLabel"]  { color: #8b949e !important; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
  [data-testid="stMetricValue"]  { color: #f0f6fc !important; font-size: 1.8rem; font-weight: 700; }
  [data-testid="stMetricDelta"]  { font-size: 0.85rem; }

  /* Tabs */
  .stTabs [data-baseweb="tab-list"] {
    background: #161b22;
    border-bottom: 2px solid #21262d;
    gap: 0;
  }
  .stTabs [data-baseweb="tab"] {
    color: #8b949e;
    border-radius: 6px 6px 0 0;
    padding: 10px 22px;
    font-weight: 600;
  }
  .stTabs [aria-selected="true"] {
    background: #1f6feb !important;
    color: #ffffff !important;
  }

  /* Section headers */
  .section-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 1.2rem 0 0.5rem 0;
    border-bottom: 1px solid #21262d;
    padding-bottom: 6px;
  }

  /* Severity badges */
  .badge-CRITICAL { background:#da3633; color:#fff; padding:3px 10px; border-radius:12px; font-weight:700; font-size:0.8rem; }
  .badge-HIGH     { background:#d29922; color:#fff; padding:3px 10px; border-radius:12px; font-weight:700; font-size:0.8rem; }
  .badge-MEDIUM   { background:#388bfd; color:#fff; padding:3px 10px; border-radius:12px; font-weight:700; font-size:0.8rem; }
  .badge-LOW      { background:#3fb950; color:#fff; padding:3px 10px; border-radius:12px; font-weight:700; font-size:0.8rem; }

  /* Alert result card */
  .alert-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 18px 22px;
    margin: 10px 0;
  }
  .alert-card h3 { color: #f0f6fc; margin: 0 0 8px 0; }
  .alert-card p  { color: #8b949e; margin: 4px 0; font-size: 0.9rem; }

  /* Dividers */
  hr { border-color: #21262d !important; }

  /* All text defaults */
  h1, h2, h3, h4, p, li, span { color: #f0f6fc; }
  .stMarkdown p { color: #c9d1d9; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_all_results() -> dict[str, dict]:
    """Return {filename_stem: metrics_dict} for all eval result files."""
    results_dir = Path(EVAL_RESULTS_DIR)
    files = sorted(results_dir.glob("metrics_*.json"), reverse=True)
    out = {}
    for f in files:
        with open(f) as fh:
            out[f.stem] = json.load(fh)
    return out


def get_model_results(all_results: dict) -> dict[str, dict]:
    """Return the most recent result for each model."""
    by_model: dict[str, dict] = {}
    for _, data in all_results.items():
        model = data.get("model", "unknown")
        if model not in by_model:
            by_model[model] = data
    return by_model


def sev_color(sev: str) -> str:
    return {"CRITICAL": "#da3633", "HIGH": "#d29922",
            "MEDIUM": "#388bfd", "LOW": "#3fb950"}.get(sev, "#8b949e")


# ── Load data ─────────────────────────────────────────────────────────────────
all_results  = load_all_results()
model_latest = get_model_results(all_results)

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## [S]️ cybersecurity")
    st.markdown("**AI-Native SOC Operations**")
    st.markdown("---")
    st.markdown("### Navigation")
    page = st.radio(
        "", ["Overview", "Model Comparison", "Cost Analysis", "Live Demo"],
        label_visibility="collapsed"
    )
    st.markdown("---")
    st.markdown("### Eval Results")
    if all_results:
        selected_file = st.selectbox(
            "Select run", list(all_results.keys()),
            format_func=lambda x: x.replace("metrics_", "").replace("_", " "),
        )
        current = all_results[selected_file]
    else:
        current = None
        st.warning("No eval results found.\nRun: `python -m eval.runner`")

    st.markdown("---")
    st.caption("Powered by GPT-4o + GPT-4o-mini\nchromaDB · FastAPI · LangChain")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
if page == "Overview":
    st.markdown("# [S]️ cybersecurity SOC Intelligence Platform")
    st.markdown("*AI-powered security alert triage — Microsoft Sentinel integration ready*")
    st.markdown("---")

    if not current:
        st.info("Run `python -m eval.runner` to generate evaluation results.")
        st.stop()

    s    = current.get("summary", {})
    c    = current.get("classification", {})
    lat  = current.get("latency", {})
    cost = current.get("cost", {})
    model_name = current.get("model", "unknown")

    # ── KPI row ───────────────────────────────────────────────────────────────
    st.markdown('<div class="section-title">Key Performance Indicators</div>', unsafe_allow_html=True)
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Alerts Analyzed",  s.get("total_alerts", 0))
    col2.metric("Accuracy",         f"{s.get('accuracy', 0):.1%}")
    col3.metric("F1 Score",         f"{c.get('f1', 0):.3f}")
    col4.metric("Groundedness",     f"{s.get('groundedness_score', 0):.1%}")
    col5.metric("Safety Pass Rate", f"{s.get('safety_pass_rate', 0):.1%}")

    st.markdown("")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Avg Latency",       f"{lat.get('mean_ms', 0):,}ms")
    col2.metric("P95 Latency",       f"{lat.get('p95_ms', 0):,}ms")
    col3.metric("Cost / Alert",      f"${cost.get('cost_per_alert_usd', 0):.5f}")
    col4.metric("Monthly @ 10K/day", f"${cost.get('projected_monthly_usd', 0):,.0f}")

    st.markdown("---")

    # ── Charts row ────────────────────────────────────────────────────────────
    try:
        import plotly.graph_objects as go
        import plotly.express as px

        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown('<div class="section-title">Classification Metrics</div>', unsafe_allow_html=True)
            metrics_vals = {
                "Precision": c.get("precision", 0),
                "Recall":    c.get("recall", 0),
                "F1 Score":  c.get("f1", 0),
                "Accuracy":  c.get("accuracy", 0),
            }
            fig = go.Figure(go.Bar(
                x=list(metrics_vals.keys()),
                y=list(metrics_vals.values()),
                marker_color=["#1f6feb", "#388bfd", "#3fb950", "#d29922"],
                text=[f"{v:.3f}" for v in metrics_vals.values()],
                textposition="outside",
            ))
            fig.update_layout(
                plot_bgcolor="#161b22", paper_bgcolor="#0d1117",
                font_color="#c9d1d9", yaxis=dict(range=[0, 1.1], gridcolor="#21262d"),
                xaxis=dict(gridcolor="#21262d"), margin=dict(t=20, b=20),
                height=280,
            )
            st.plotly_chart(fig, use_container_width=True)

        with col_right:
            st.markdown('<div class="section-title">Latency Distribution</div>', unsafe_allow_html=True)
            lat_data = {
                "Mean":   lat.get("mean_ms", 0),
                "Median": lat.get("median_ms", 0),
                "P95":    lat.get("p95_ms", 0),
                "P99":    lat.get("p99_ms", 0),
            }
            fig2 = go.Figure(go.Bar(
                x=list(lat_data.keys()),
                y=list(lat_data.values()),
                marker_color="#1f6feb",
                text=[f"{v:,}ms" for v in lat_data.values()],
                textposition="outside",
            ))
            fig2.update_layout(
                plot_bgcolor="#161b22", paper_bgcolor="#0d1117",
                font_color="#c9d1d9", yaxis=dict(gridcolor="#21262d"),
                xaxis=dict(gridcolor="#21262d"), margin=dict(t=20, b=20),
                height=280,
            )
            st.plotly_chart(fig2, use_container_width=True)

    except ImportError:
        st.info("Install plotly for charts: `pip install plotly`")

    st.markdown("---")
    st.markdown(f"**Active model:** `{model_name}` &nbsp;|&nbsp; "
                f"**Evaluated:** {current.get('evaluated_at', 'N/A')[:10]}",
                unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: MODEL COMPARISON
# ══════════════════════════════════════════════════════════════════════════════
elif page == "Model Comparison":
    st.markdown("# [FAST] GPT-4o vs GPT-4o-mini")
    st.markdown("*Side-by-side quality and cost tradeoff analysis*")
    st.markdown("---")

    m4o   = model_latest.get("gpt-4o", {})
    mmini = model_latest.get("gpt-4o-mini", {})

    if not m4o and not mmini:
        st.warning("Run evaluation for both models first:\n"
                   "```\npython -m eval.runner --model gpt-4o\n"
                   "python -m eval.runner --model gpt-4o-mini\n```")
        st.stop()

    def s(d, *keys):
        val = d
        for k in keys:
            val = val.get(k, {}) if isinstance(val, dict) else 0
        return val if val != {} else 0

    # ── Header cards ─────────────────────────────────────────────────────────
    col1, col_mid, col2 = st.columns([5, 1, 5])

    with col1:
        st.markdown("### [*] GPT-4o")
        st.caption("Highest accuracy · Recommended for HIGH/CRITICAL")
        if m4o:
            c1, c2, c3 = st.columns(3)
            c1.metric("F1 Score",  f"{s(m4o, 'classification', 'f1'):.3f}")
            c2.metric("Accuracy",  f"{s(m4o, 'summary', 'accuracy'):.1%}")
            c3.metric("Latency",   f"{s(m4o, 'latency', 'mean_ms'):,}ms")
        else:
            st.info("No GPT-4o results yet.")

    with col_mid:
        st.markdown("<br><br><center style='color:#8b949e;font-size:1.5rem'>VS</center>",
                    unsafe_allow_html=True)

    with col2:
        st.markdown("### [GO] GPT-4o-mini")
        st.caption("33x cheaper · Recommended for LOW/MEDIUM volume")
        if mmini:
            c1, c2, c3 = st.columns(3)
            c1.metric("F1 Score",  f"{s(mmini, 'classification', 'f1'):.3f}")
            c2.metric("Accuracy",  f"{s(mmini, 'summary', 'accuracy'):.1%}")
            c3.metric("Latency",   f"{s(mmini, 'latency', 'mean_ms'):,}ms")
        else:
            st.info("No GPT-4o-mini results yet.")

    st.markdown("---")

    # ── Comparison chart ──────────────────────────────────────────────────────
    try:
        import plotly.graph_objects as go

        st.markdown('<div class="section-title">Quality Metrics Comparison</div>', unsafe_allow_html=True)
        metrics = ["Precision", "Recall", "F1", "Groundedness", "Safety"]
        v4o   = [
            s(m4o,   "classification", "precision"),
            s(m4o,   "classification", "recall"),
            s(m4o,   "classification", "f1"),
            s(m4o,   "summary", "groundedness_score"),
            s(m4o,   "summary", "safety_pass_rate"),
        ]
        vmini = [
            s(mmini, "classification", "precision"),
            s(mmini, "classification", "recall"),
            s(mmini, "classification", "f1"),
            s(mmini, "summary", "groundedness_score"),
            s(mmini, "summary", "safety_pass_rate"),
        ]

        fig = go.Figure()
        if m4o:
            fig.add_trace(go.Bar(
                name="GPT-4o", x=metrics, y=v4o,
                marker_color="#1f6feb",
                text=[f"{v:.3f}" for v in v4o], textposition="outside",
            ))
        if mmini:
            fig.add_trace(go.Bar(
                name="GPT-4o-mini", x=metrics, y=vmini,
                marker_color="#3fb950",
                text=[f"{v:.3f}" for v in vmini], textposition="outside",
            ))
        fig.update_layout(
            barmode="group",
            plot_bgcolor="#161b22", paper_bgcolor="#0d1117",
            font_color="#c9d1d9", legend=dict(bgcolor="#161b22"),
            yaxis=dict(range=[0, 1.15], gridcolor="#21262d"),
            xaxis=dict(gridcolor="#21262d"),
            margin=dict(t=30, b=20), height=340,
        )
        st.plotly_chart(fig, use_container_width=True)

        # ── Cost vs quality scatter ───────────────────────────────────────────
        if m4o and mmini:
            st.markdown("---")
            st.markdown('<div class="section-title">Cost vs Quality Tradeoff</div>', unsafe_allow_html=True)
            col_l, col_r = st.columns(2)

            with col_l:
                cost_4o   = s(m4o,   "cost", "projected_monthly_usd")
                cost_mini = s(mmini, "cost", "projected_monthly_usd")
                savings   = cost_4o - cost_mini
                savings_p = savings / max(cost_4o, 0.01) * 100

                fig3 = go.Figure()
                fig3.add_trace(go.Bar(
                    x=["GPT-4o", "GPT-4o-mini", "Smart Routing (~40% 4o)"],
                    y=[cost_4o, cost_mini, cost_mini + (cost_4o - cost_mini) * 0.4],
                    marker_color=["#1f6feb", "#3fb950", "#d29922"],
                    text=[f"${v:,.0f}" for v in [
                        cost_4o, cost_mini,
                        cost_mini + (cost_4o - cost_mini) * 0.4
                    ]],
                    textposition="outside",
                ))
                fig3.update_layout(
                    title=dict(text="Monthly Cost @ 10K alerts/day", font_color="#c9d1d9"),
                    plot_bgcolor="#161b22", paper_bgcolor="#0d1117",
                    font_color="#c9d1d9",
                    yaxis=dict(gridcolor="#21262d", tickprefix="$"),
                    xaxis=dict(gridcolor="#21262d"),
                    margin=dict(t=50, b=20), height=300,
                )
                st.plotly_chart(fig3, use_container_width=True)

            with col_r:
                st.markdown(f"""
<div class="alert-card">
  <h3>Smart Routing Strategy</h3>
  <p><b style="color:#3fb950">Pass 1</b> — gpt-4o-mini screens all alerts (fast + cheap)</p>
  <p><b style="color:#1f6feb">Pass 2</b> — gpt-4o re-analyzes HIGH/CRITICAL only</p>
  <hr style="border-color:#30363d">
  <p>All-gpt-4o cost:&nbsp;&nbsp;&nbsp; <b style="color:#da3633">${cost_4o:,.0f}/mo</b></p>
  <p>All-mini cost:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <b style="color:#3fb950">${cost_mini:,.0f}/mo</b></p>
  <p>Smart routing:&nbsp;&nbsp;&nbsp;&nbsp; <b style="color:#d29922">${cost_mini + (cost_4o - cost_mini) * 0.4:,.0f}/mo</b></p>
  <hr style="border-color:#30363d">
  <p style="font-size:1.1rem"><b style="color:#3fb950">~{savings_p:.0f}% savings</b> vs all-gpt-4o</p>
</div>
""", unsafe_allow_html=True)

    except ImportError:
        st.info("Install plotly: `pip install plotly`")

    # ── Comparison table ──────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown('<div class="section-title">Full Metrics Table</div>', unsafe_allow_html=True)

    rows = []
    metric_defs = [
        ("Groundedness",    "summary",        "groundedness_score", "{:.1%}"),
        ("Precision",       "classification", "precision",          "{:.3f}"),
        ("Recall",          "classification", "recall",             "{:.3f}"),
        ("F1 Score",        "classification", "f1",                 "{:.3f}"),
        ("Accuracy",        "classification", "accuracy",           "{:.1%}"),
        ("Safety Pass",     "summary",        "safety_pass_rate",   "{:.1%}"),
        ("Avg Latency",     "latency",        "mean_ms",            "{:,}ms"),
        ("P95 Latency",     "latency",        "p95_ms",             "{:,}ms"),
        ("Cost/alert",      "cost",           "cost_per_alert_usd", "${:.5f}"),
        ("Monthly @10K/day","cost",           "projected_monthly_usd","${:,.0f}"),
    ]
    for label, section, key, fmt in metric_defs:
        v4  = s(m4o,   section, key)
        vm  = s(mmini, section, key)
        better = ""
        if isinstance(v4, (int, float)) and isinstance(vm, (int, float)):
            if key in ("mean_ms", "p95_ms", "p95_ms", "cost_per_alert_usd", "projected_monthly_usd"):
                better = "mini" if vm < v4 else "4o"
            else:
                better = "4o" if v4 > vm else "mini"
        rows.append({
            "Metric": label,
            "GPT-4o":      fmt.format(v4)  if isinstance(v4, (int, float)) else str(v4),
            "GPT-4o-mini": fmt.format(vm)  if isinstance(vm, (int, float)) else str(vm),
            "Winner": "[*] GPT-4o" if better == "4o" else ("[GO] mini" if better == "mini" else "—"),
        })

    import pandas as pd
    df = pd.DataFrame(rows)
    st.dataframe(
        df.style.applymap(
            lambda v: "color: #3fb950" if "mini" in str(v) else ("color: #388bfd" if "4o" in str(v) else ""),
            subset=["Winner"]
        ),
        use_container_width=True, hide_index=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: COST ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
elif page == "Cost Analysis":
    st.markdown("# [$] Cost Analysis & Projections")
    st.markdown("*ROI calculator for enterprise SOC deployment*")
    st.markdown("---")

    try:
        import plotly.graph_objects as go
        import numpy as np

        # ── Sliders ───────────────────────────────────────────────────────────
        st.markdown('<div class="section-title">Configure Your Environment</div>', unsafe_allow_html=True)
        col1, col2, col3 = st.columns(3)
        daily_alerts   = col1.slider("Daily alerts",           1_000, 100_000, 10_000, 1_000)
        pct_high_crit  = col2.slider("% HIGH/CRITICAL alerts", 5, 60, 30) / 100
        analyst_hourly = col3.slider("SOC analyst hourly rate ($)", 40, 150, 75)

        # ── Cost math ─────────────────────────────────────────────────────────
        cost_per_alert_4o   = 0.00320
        cost_per_alert_mini = 0.00080
        # Smart routing: HIGH/CRIT get 4o, rest get mini
        cost_per_alert_routed = (pct_high_crit * cost_per_alert_4o +
                                 (1 - pct_high_crit) * cost_per_alert_mini)

        monthly_4o      = cost_per_alert_4o      * daily_alerts * 30
        monthly_mini    = cost_per_alert_mini    * daily_alerts * 30
        monthly_routed  = cost_per_alert_routed  * daily_alerts * 30

        # Human analyst: assume 15min per alert triage manually
        analyst_monthly = (daily_alerts * 30 * 0.25) * analyst_hourly

        st.markdown("---")
        st.markdown('<div class="section-title">Monthly Cost Projections</div>', unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("All GPT-4o",          f"${monthly_4o:,.0f}",
                  delta=f"-${monthly_4o - monthly_routed:,.0f} vs routing",
                  delta_color="inverse")
        c2.metric("All GPT-4o-mini",     f"${monthly_mini:,.0f}")
        c3.metric("Smart Routing",       f"${monthly_routed:,.0f}",
                  delta=f"{(1 - monthly_routed/monthly_4o)*100:.0f}% savings vs all-4o")
        c4.metric("Human Analysts",      f"${analyst_monthly:,.0f}",
                  delta=f"{(1 - monthly_routed/analyst_monthly)*100:.0f}% cheaper than humans")

        st.markdown("")

        # ── Bar chart ─────────────────────────────────────────────────────────
        fig = go.Figure(go.Bar(
            x=["All GPT-4o", "Smart Routing", "All GPT-4o-mini", "Human Analysts"],
            y=[monthly_4o, monthly_routed, monthly_mini, analyst_monthly],
            marker_color=["#1f6feb", "#d29922", "#3fb950", "#da3633"],
            text=[f"${v:,.0f}" for v in [monthly_4o, monthly_routed, monthly_mini, analyst_monthly]],
            textposition="outside",
        ))
        fig.update_layout(
            title=dict(text=f"Monthly Cost at {daily_alerts:,} alerts/day", font_color="#c9d1d9"),
            plot_bgcolor="#161b22", paper_bgcolor="#0d1117",
            font_color="#c9d1d9",
            yaxis=dict(gridcolor="#21262d", tickprefix="$"),
            xaxis=dict(gridcolor="#21262d"),
            margin=dict(t=50, b=20), height=380,
        )
        st.plotly_chart(fig, use_container_width=True)

        # ── Break-even chart ──────────────────────────────────────────────────
        st.markdown("---")
        st.markdown('<div class="section-title">Annual ROI vs Human Analysts</div>', unsafe_allow_html=True)
        annual_ai      = monthly_routed * 12
        annual_humans  = analyst_monthly * 12
        annual_savings = annual_humans - annual_ai

        col_l, col_r = st.columns(2)
        col_l.metric("Annual AI Cost (Smart Routing)", f"${annual_ai:,.0f}")
        col_r.metric("Annual Savings vs Analysts",     f"${annual_savings:,.0f}",
                     delta=f"{annual_savings/annual_humans*100:.0f}% ROI")

        months = list(range(1, 13))
        cumulative_ai     = [monthly_routed    * m for m in months]
        cumulative_humans = [analyst_monthly   * m for m in months]

        fig2 = go.Figure()
        fig2.add_trace(go.Scatter(
            x=months, y=cumulative_humans,
            name="Human Analysts", line=dict(color="#da3633", width=2),
            fill="tozeroy", fillcolor="rgba(218,54,51,0.1)",
        ))
        fig2.add_trace(go.Scatter(
            x=months, y=cumulative_ai,
            name="cybersecurity (Smart Routing)", line=dict(color="#3fb950", width=2),
            fill="tozeroy", fillcolor="rgba(63,185,80,0.1)",
        ))
        fig2.update_layout(
            xaxis_title="Month", yaxis_title="Cumulative Cost ($)",
            plot_bgcolor="#161b22", paper_bgcolor="#0d1117",
            font_color="#c9d1d9", legend=dict(bgcolor="#161b22"),
            yaxis=dict(gridcolor="#21262d", tickprefix="$"),
            xaxis=dict(gridcolor="#21262d", tickmode="linear"),
            margin=dict(t=20, b=20), height=320,
        )
        st.plotly_chart(fig2, use_container_width=True)

    except ImportError:
        st.info("Install plotly + numpy: `pip install plotly numpy`")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: LIVE DEMO
# ══════════════════════════════════════════════════════════════════════════════
elif page == "Live Demo":
    st.markdown("# [STOP] Live Alert Triage")
    st.markdown("*Submit a real security alert and watch cybersecurity analyze it in real-time*")
    st.markdown("---")

    DEMO_PRESETS = {
        "Impossible Travel (Tor Exit Node)": {
            "alert_id": "LIVE-001", "type": "suspicious_login",
            "user": "john.doe@company.com", "source_ip": "185.220.101.45",
            "location": "Romania", "prev_location": "New York, USA",
            "time_gap_hours": 2.0, "timestamp": "2024-01-15T03:14:00Z",
        },
        "WannaCry Ransomware Detected": {
            "alert_id": "LIVE-002", "type": "malware_detected",
            "hostname": "WORKSTATION-42",
            "file_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
            "process_name": "svchost.exe",
            "description": "Suspicious process spawned from user temp directory",
        },
        "Low-Risk Internal Login": {
            "alert_id": "LIVE-003", "type": "suspicious_login",
            "user": "alice@company.com", "source_ip": "192.168.1.100",
            "location": "New York, USA", "prev_location": "Boston, USA",
            "time_gap_hours": 5.0,
        },
        "APT C2 Beacon (Cobalt Strike)": {
            "alert_id": "LIVE-004", "type": "malware_detected",
            "hostname": "LAPTOP-99",
            "file_hash": "abc123def456789012345678901234ab",
            "process_name": "beacon.exe",
            "description": "Unknown executable communicating with 203.0.113.45",
        },
    }

    col_l, col_r = st.columns([2, 3])

    with col_l:
        st.markdown("### Configure Alert")
        preset = st.selectbox("Quick preset", ["Custom"] + list(DEMO_PRESETS.keys()))
        if preset != "Custom":
            default_json = json.dumps(DEMO_PRESETS[preset], indent=2)
        else:
            default_json = json.dumps({
                "alert_id": "CUSTOM-001",
                "type": "suspicious_login",
                "source_ip": "185.220.101.45",
                "location": "Romania",
                "prev_location": "New York, USA",
                "time_gap_hours": 2.0,
            }, indent=2)

        alert_json = st.text_area("Alert JSON", value=default_json, height=250)
        model_sel  = st.radio("Model", ["gpt-4o-mini", "gpt-4o"], horizontal=True)
        use_routing = st.checkbox("Use two-pass routing")
        run_btn    = st.button("Analyze Alert", type="primary", use_container_width=True)

    with col_r:
        st.markdown("### Analysis Result")
        if run_btn:
            try:
                raw_alert = json.loads(alert_json)
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")
                st.stop()

            with st.spinner("cybersecurity is analyzing..."):
                from agent.agent import SecurityAgent
                agent  = SecurityAgent(model=model_sel)
                result = (agent.analyze_with_routing(raw_alert) if use_routing
                          else agent.analyze(raw_alert))

            sev   = result.get("severity", "UNKNOWN")
            conf  = result.get("confidence", 0)
            color = sev_color(sev)

            st.markdown(f"""
<div class="alert-card">
  <span class="badge-{sev}">{sev}</span>&nbsp;&nbsp;
  <b style="color:#8b949e">Confidence: {conf:.0%}</b>&nbsp;&nbsp;
  <b style="color:#8b949e">Latency: {result.get('latency_ms',0):,}ms</b>
  <hr style="border-color:#30363d; margin:12px 0">
  <p><b style="color:#c9d1d9">Explanation:</b><br>{result.get('explanation','')}</p>
  <hr style="border-color:#30363d; margin:12px 0">
  <p><b style="color:#c9d1d9">Recommended Actions:</b></p>
  {''.join(f"<p>• {a}</p>" for a in result.get('recommended_actions', []))}
  <p><b style="color:#c9d1d9">MITRE Techniques:</b> {', '.join(result.get('mitre_techniques', [])) or 'None'}</p>
  <p><b style="color:#c9d1d9">Tools Used:</b> {', '.join(result.get('tool_calls_made', [])) or 'None'}</p>
  <p><b style="color:#c9d1d9">Model:</b> {result.get('model_used','?')} &nbsp;|&nbsp;
     <b style="color:#c9d1d9">Cost:</b> ${result.get('estimated_cost_usd',0):.5f}</p>
</div>
""", unsafe_allow_html=True)

            if result.get("routing_escalated"):
                st.info(f"Routed: gpt-4o-mini -> gpt-4o  "
                        f"(Pass 1 severity: {result.get('pass1_severity')})")

            with st.expander("Raw JSON"):
                st.json(result)
        else:
            st.markdown("""
<div class="alert-card">
  <p style="color:#8b949e; text-align:center; padding: 40px 0;">
    Select a preset or enter a custom alert JSON,<br>then click <b>Analyze Alert</b>.
  </p>
</div>
""", unsafe_allow_html=True)
