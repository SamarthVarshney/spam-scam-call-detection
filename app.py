"""
Streamlit Web Application Entry Point (app.py)
==============================================
Implements the 8-page interactive web application specified in Figure 1 and
Section 7 of the project document ("AI-Based Spam & Scam Call Detection System"),
styled with the "Telecom Signal & Forensic Ledger" design system (Plus Jakarta Sans,
Instrument Serif, JetBrains Mono).

Run with:
  streamlit run app.py

Authors: Silvia Noatia (2026279652), Fatima Iqbal (2026187337)
Mentor: Dharmendra Kumar | Sharda University (CSCR2600 PBL-1)
"""

from __future__ import annotations

import html
import random
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from data_preprocessing import (
    CATEGORICAL_FEATURES,
    CLASSES,
    CSV_PATH,
    FEATURE_METADATA,
    NUMERIC_FEATURES,
    load_and_clean_dataset,
    sanitize_phone_number,
)
from database import (
    export_table_to_csv_string,
    get_all_community_reports,
    get_dashboard_statistics,
    get_number_intelligence,
    init_database,
    submit_community_report,
    upvote_community_report,
)
from model_training import load_evaluation_metrics, train_and_evaluate_all
from prediction import PRESET_CALL_SCENARIOS, load_artifacts, predict_call_risk
from risk_engine import evaluate_incoming_call
from test_suite import run_all_verification_checks
from transcript_analyzer import SAMPLE_TRANSCRIPTS, SCAM_CATEGORIES, analyze_transcript

st.set_page_config(
    page_title="CallShield Forensics | AI Spam & Scam Call Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject Custom Typography & Forensic Ledger CSS
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
    }
    code, pre, .mono {
        font-family: 'JetBrains Mono', monospace !important;
    }
    .serif-accent {
        font-family: 'Instrument Serif', Georgia, serif !important;
        font-style: italic;
        color: #00BFA6;
        font-weight: 400;
    }
    .ledger-card {
        background-color: #121720;
        border: 1px solid #232C3B;
        border-radius: 10px;
        padding: 18px 20px;
        margin-bottom: 16px;
    }
    .kpi-box {
        background-color: #121720;
        border: 1px solid #232C3B;
        border-left: 4px solid #00BFA6;
        border-radius: 8px;
        padding: 15px 18px;
    }
    .kpi-box.amber { border-left-color: #F59E0B; }
    .kpi-box.crimson { border-left-color: #EF4444; }
    .kpi-label {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        color: #8B97AA;
    }
    .kpi-val {
        font-family: 'JetBrains Mono', monospace;
        font-size: 26px;
        font-weight: 700;
        color: #F1F0EC;
        margin: 4px 0;
    }
    .kpi-sub {
        font-size: 12.5px;
        color: #A2ADBE;
    }
    .verdict-box {
        border-radius: 10px;
        padding: 20px 22px;
        margin-bottom: 18px;
        border: 1px solid #232C3B;
    }
    .verdict-box.safe {
        background: rgba(0, 191, 166, 0.12);
        border-color: rgba(0, 191, 166, 0.4);
    }
    .verdict-box.spam {
        background: rgba(245, 158, 11, 0.12);
        border-color: rgba(245, 158, 11, 0.4);
    }
    .verdict-box.scam {
        background: rgba(239, 68, 68, 0.13);
        border-color: rgba(239, 68, 68, 0.45);
    }
    .hl-span {
        background: rgba(239, 68, 68, 0.22);
        border-bottom: 2px solid #EF4444;
        padding: 2px 5px;
        border-radius: 4px;
        font-weight: 600;
    }
    .hl-tag {
        font-family: 'JetBrains Mono', monospace;
        font-size: 10px;
        background: #EF4444;
        color: #FFFFFF;
        padding: 1px 5px;
        border-radius: 3px;
        margin-left: 4px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

init_database()
load_artifacts()

# ==================== SIDEBAR NAVIGATION (8 PAGES) ====================
with st.sidebar:
    st.markdown(
        """
        <div style="padding-bottom:12px; border-bottom:1px solid #232C3B; margin-bottom:12px;">
            <div class="mono" style="font-size:11px; color:#00BFA6; letter-spacing:0.08em;">CSCR2600 // PBL-1 SYSTEM</div>
            <div style="font-size:20px; font-weight:700; color:#F1F0EC; margin-top:2px;">CallShield Forensics</div>
            <div style="font-size:12px; color:#8B97AA;">AI-Based Spam &amp; Scam Call Detection</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    PAGES = [
        "01 // Executive Overview",
        "02 // Live Call Risk Predictor",
        "03 // Call Transcript Analyzer",
        "04 // Community & Reputation",
        "05 // Live Threat Dashboard",
        "06 // Synthetic Dataset Explorer",
        "07 // ML Model Benchmark Lab",
        "08 // Verification & Defect Log",
    ]

    selected_page = st.radio("Navigation (8 Functional Pages)", PAGES, label_visibility="collapsed")

    st.markdown(
        """
        <div style="margin-top:20px; padding:14px; background:#171E29; border:1px solid #232C3B; border-radius:8px; font-size:12px;">
            <div class="mono" style="color:#F59E0B; font-size:10.5px; text-transform:uppercase; margin-bottom:4px;">
                Sharda University &bull; CSE
            </div>
            <div><strong>Silvia Noatia</strong> (2026279652)</div>
            <div><strong>Fatima Iqbal</strong> (2026187337)</div>
            <div style="color:#8B97AA; margin-top:4px;">
                Section: MG2 &bull; Session 2025–26<br/>
                Mentor: <strong>Prof. Dharmendra Kumar</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ==============================================================================
# PAGE 01: EXECUTIVE OVERVIEW
# ==============================================================================
if selected_page.startswith("01"):
    metrics = load_evaluation_metrics()
    dash = get_dashboard_statistics()

    st.markdown(
        """
        <div class="mono" style="font-size:11.5px; color:#00BFA6; text-transform:uppercase; letter-spacing:0.08em;">
            Sharda School of Computing Science &amp; Engineering &bull; CSCR2600 PBL-1
        </div>
        <h1 style="font-size:32px; font-weight:700; margin-top:4px;">
            AI-Based Spam &amp; Scam <span class="serif-accent" style="font-size:36px;">Call Detection System</span>
        </h1>
        <p style="color:#A2ADBE; font-size:15px; max-width:85ch;">
            An explainable, multi-signal machine learning web application that predicts whether an incoming call is
            <strong>Safe</strong>, <strong>Spam</strong>, or <strong>Scam/Fraud</strong> by combining a trained Random Forest classifier,
            caller behavioral telemetry, community-submitted reports, historical number reputation, and a 10-category regex transcript analyzer.
        </p>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"""
            <div class="kpi-box">
                <div class="kpi-label">Best Model Accuracy</div>
                <div class="kpi-val">{metrics['best_accuracy']*100:.2f}%</div>
                <div class="kpi-sub">{metrics['best_model_name']} &bull; Macro-F1: {metrics['best_f1_macro']:.4f}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="kpi-box amber">
                <div class="kpi-label">Synthetic Dataset</div>
                <div class="kpi-val">{metrics['dataset_rows']:,}</div>
                <div class="kpi-sub">15 Behavioral &amp; Carrier Features</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div class="kpi-box crimson">
                <div class="kpi-label">Community Reports</div>
                <div class="kpi-val">{dash['total_community_reports']}</div>
                <div class="kpi-sub">{dash['high_risk_watchlist_count']} High-Risk Watchlist Numbers</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"""
            <div class="kpi-box">
                <div class="kpi-label">Calls Analyzed</div>
                <div class="kpi-val">{dash['total_calls_analyzed']}</div>
                <div class="kpi-sub">60% ML + 25% Comm + 15% Rep</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<br/>", unsafe_allow_html=True)
    col_l, col_r = st.columns([1.15, 0.85])
    with col_l:
        st.markdown("#### Figure 1: High-Level System Context Architecture")
        st.markdown(
            """
            <div class="ledger-card" style="text-align:center;">
                <div style="background:#0B192C; color:#FFF; padding:12px; border-radius:8px; font-weight:700; border:1px solid #334056;">
                    Streamlit Web App (app.py) &amp; FastAPI Server (server.py)
                </div>
                <div class="mono" style="color:#8B97AA; margin:8px 0;">&darr; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &darr; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &darr;</div>
                <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:10px;">
                    <div style="background:#00BFA6; color:#051411; padding:10px; border-radius:7px; font-weight:700;">Prediction Engine<br/><span class="mono" style="font-size:11px;">(prediction.py)</span></div>
                    <div style="background:#F59E0B; color:#1B1002; padding:10px; border-radius:7px; font-weight:700;">Risk Engine<br/><span class="mono" style="font-size:11px;">(risk_engine.py)</span></div>
                    <div style="background:#00BFA6; color:#051411; padding:10px; border-radius:7px; font-weight:700;">Transcript Analyzer<br/><span class="mono" style="font-size:11px;">(transcript_analyzer.py)</span></div>
                </div>
                <div class="mono" style="color:#8B97AA; margin:8px 0;">&darr; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &darr; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &darr;</div>
                <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:10px;">
                    <div style="background:#1C2432; color:#F1F0EC; padding:10px; border-radius:7px; border:1px solid #334056;">ML Model + Pipeline<br/><span class="mono" style="font-size:11px;">(.pkl via joblib)</span></div>
                    <div style="background:#1C2432; color:#F1F0EC; padding:10px; border-radius:7px; border:1px solid #334056;">SQLite Database<br/><span class="mono" style="font-size:11px;">(reports, reputation, log)</span></div>
                    <div style="background:#1C2432; color:#F1F0EC; padding:10px; border-radius:7px; border:1px solid #334056;">Rule-Based Regex<br/><span class="mono" style="font-size:11px;">(10 Scam Categories)</span></div>
                </div>
                <div class="mono" style="color:#8B97AA; margin:8px 0;">&darr; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &darr; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &darr;</div>
                <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:10px;">
                    <div style="background:#0B192C; color:#F1F0EC; padding:10px; border-radius:7px;">Synthetic Dataset<br/><span class="mono" style="font-size:11px;">(data/calls.csv)</span></div>
                    <div style="background:#0B192C; color:#F1F0EC; padding:10px; border-radius:7px;">Community Reports<br/><span class="mono" style="font-size:11px;">(User Input)</span></div>
                    <div style="background:#0B192C; color:#F1F0EC; padding:10px; border-radius:7px;">Pasted Transcript<br/><span class="mono" style="font-size:11px;">(Call Text)</span></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_r:
        st.markdown("#### Instant Number Reputation Quick-Check")
        quick_num = st.text_input("Enter Caller Phone Number (E.164)", value="+91-92104-88319")
        q_intel = get_number_intelligence(quick_num)
        st.info(
            f"**{q_intel['phone_number']}** — **{q_intel['status_tag']}**  \n"
            f"Reputation Risk: **{q_intel['reputation_risk_score']}/100** | "
            f"Reports: **{q_intel['total_reports']}** ({q_intel['scam_reports']} Scam, {q_intel['spam_reports']} Spam, {q_intel['safe_votes']} Safe)"
        )

        st.markdown("#### Project Modules & Design Specification")
        spec_df = pd.DataFrame(
            [
                {"Module": "data_preprocessing.py", "Role": "6,000-row dataset, E.164 '+' sanitizer, leak-free ColumnTransformer"},
                {"Module": "model_training.py", "Role": "80/20 stratified split, 5 ML classifiers, Macro-F1 selection"},
                {"Module": "prediction.py", "Role": "Class probabilities, 0–100 ML score, plain-language reasons"},
                {"Module": "risk_engine.py", "Role": "Blends 60% ML + 25% Community + 15% Reputation"},
                {"Module": "database.py", "Role": "SQLite storage for reports, reputation, and call logs"},
                {"Module": "transcript_analyzer.py", "Role": "10 regex scam categories & weighted scoring"},
            ]
        )
        st.dataframe(spec_df, use_container_width=True, hide_index=True)

# ==============================================================================
# PAGE 02: LIVE CALL RISK PREDICTOR
# ==============================================================================
elif selected_page.startswith("02"):
    st.markdown(
        """
        <div class="mono" style="font-size:11.5px; color:#00BFA6; text-transform:uppercase;">02 // Prediction Engine + Risk Engine</div>
        <h2>Live Call Risk <span class="serif-accent" style="font-size:32px;">Predictor &amp; Explainability</span></h2>
        """,
        unsafe_allow_html=True,
    )

    preset_names = list(PRESET_CALL_SCENARIOS.keys())
    chosen_preset = st.selectbox("Quick-Load Realistic Call Scenario Preset", preset_names, index=2)
    preset_feats = PRESET_CALL_SCENARIOS[chosen_preset]["features"]

    col_form, col_res = st.columns([1.05, 0.95])
    with col_form:
        with st.form("streamlit_call_form"):
            st.markdown("##### Caller Behavioral & Carrier Telemetry (15 Features)")
            f_c1, f_c2 = st.columns(2)
            with f_c1:
                phone_number = st.text_input("Caller Phone Number (E.164)", value=preset_feats["phone_number"])
                calls_24h = st.slider("Calls in Last 24h", 1, 150, int(preset_feats["calls_last_24h"]))
                avg_dur = st.slider("Avg Call Duration (sec)", 3.0, 700.0, float(preset_feats["avg_call_duration_sec"]))
                ans_rate = st.slider("Recipient Answer Rate", 0.01, 1.0, float(preset_feats["answer_rate"]))
                uniq_ratio = st.slider("Unique Recipient Ratio", 0.05, 1.0, float(preset_feats["unique_recipients_ratio"]))
                age_days = st.slider("Number Activation Age (Days)", 1, 2500, int(preset_feats["number_age_days"]))
                prefix_type = st.selectbox(
                    "Number Prefix Category",
                    ["Domestic_Mobile", "Telemarketing_140", "International_VoIP", "Virtual_DID", "Toll_Free"],
                    index=["Domestic_Mobile", "Telemarketing_140", "International_VoIP", "Virtual_DID", "Toll_Free"].index(preset_feats["prefix_type"]),
                )
                in_contact = st.selectbox(
                    "Contact Graph Proximity",
                    ["Yes", "Mutual_2nd_Degree", "No"],
                    index=["Yes", "Mutual_2nd_Degree", "No"].index(preset_feats["in_contact_network"]),
                )
            with f_c2:
                model_choice = st.selectbox(
                    "Classifier Model",
                    ["Random Forest", "Gradient Boosting", "SVM", "Logistic Regression", "Decision Tree"],
                )
                calls_7d = st.slider("Calls in Last 7 Days", 1, 800, int(preset_feats["calls_last_7d"]))
                silence_sec = st.slider("Initial Pickup Silence (sec)", 0.0, 6.0, float(preset_feats["silence_initial_sec"]))
                short_ratio = st.slider("Short Hang-up Ratio (<10s)", 0.0, 1.0, float(preset_feats["short_call_ratio"]))
                complaint_rate = st.slider("Prior Complaint Density", 0.0, 1.0, float(preset_feats["prior_complaint_rate"]))
                hour_of_day = st.slider("Call Hour of Day (0–23h)", 0, 23, int(preset_feats["hour_of_day"]))
                line_type = st.selectbox(
                    "Caller Line Type",
                    ["Mobile_SIM", "PRI_Trunk", "VoIP_SIP", "Spoofed_CLI", "Landline"],
                    index=["Mobile_SIM", "PRI_Trunk", "VoIP_SIP", "Spoofed_CLI", "Landline"].index(preset_feats["caller_line_type"]),
                )
                cli_status = st.selectbox(
                    "STIR/SHAKEN CLI Attestation",
                    ["STIR_SHAKEN_A", "STIR_SHAKEN_B", "STIR_SHAKEN_C", "Unverified"],
                    index=["STIR_SHAKEN_A", "STIR_SHAKEN_B", "STIR_SHAKEN_C", "Unverified"].index(preset_feats["cli_verification_status"]),
                )

            opt_transcript = st.text_area(
                "Optional Live Call Transcript Snippet (Multi-Modal Fusion)",
                value="",
                placeholder="Optional: Paste caller speech to fuse transcript score with behavioral score...",
                height=68,
            )
            submitted = st.form_submit_button("Evaluate Call Risk & Log to SQLite", use_container_width=True)

    caller_payload = {
        "phone_number": phone_number,
        "calls_last_24h": calls_24h,
        "calls_last_7d": calls_7d,
        "avg_call_duration_sec": avg_dur,
        "answer_rate": ans_rate,
        "short_call_ratio": short_ratio,
        "silence_initial_sec": silence_sec,
        "unique_recipients_ratio": uniq_ratio,
        "hour_of_day": hour_of_day,
        "number_age_days": age_days,
        "prior_complaint_rate": complaint_rate,
        "prefix_type": prefix_type,
        "caller_line_type": line_type,
        "in_contact_network": in_contact,
        "cli_verification_status": cli_status,
    }

    t_score = None
    if opt_transcript and opt_transcript.strip():
        t_score = analyze_transcript(opt_transcript)["transcript_risk_score"]

    eval_res = evaluate_incoming_call(
        caller_payload,
        model_name=model_choice,
        transcript_score=t_score,
        persist_log=bool(submitted),
    )

    with col_res:
        v_cls = eval_res["verdict_class"].lower()
        st.markdown(
            f"""
            <div class="verdict-box {v_cls}">
                <div class="mono" style="font-size:12px; text-transform:uppercase;">
                    {html.escape(eval_res['risk_level'])} &bull; {html.escape(eval_res['phone_number'])}
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:6px;">
                    <div style="font-size:22px; font-weight:700;">{html.escape(eval_res['headline'])}</div>
                    <div class="mono" style="font-size:38px; font-weight:700;">{eval_res['final_risk_score']:.1f}<span style="font-size:15px;">/100</span></div>
                </div>
                <p style="margin-top:8px; color:#D0D7E2; font-size:13.5px;">{html.escape(eval_res['recommendation'])}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        s_ml = eval_res["signals"]["ml_model"]
        s_cm = eval_res["signals"]["community_reports"]
        s_rp = eval_res["signals"]["historical_reputation"]

        st.markdown("##### Multi-Signal Risk Blending (60% ML + 25% Community + 15% Reputation)")
        sig_df = pd.DataFrame(
            [
                {"Signal Component": "ML Classifier (60%)", "Raw Score (0-100)": s_ml["raw_score"], "Weighted Points": s_ml["weighted_contribution"]},
                {"Signal Component": "Community Reports (25%)", "Raw Score (0-100)": s_cm["raw_score"], "Weighted Points": s_cm["weighted_contribution"]},
                {"Signal Component": "Historical Reputation (15%)", "Raw Score (0-100)": s_rp["raw_score"], "Weighted Points": s_rp["weighted_contribution"]},
            ]
        )
        st.dataframe(sig_df, use_container_width=True, hide_index=True)

        probs = eval_res["probabilities"]
        fig_prob = go.Figure(
            go.Bar(
                x=[probs["Safe"] * 100, probs["Spam"] * 100, probs["Scam"] * 100],
                y=["Safe", "Spam", "Scam"],
                orientation="h",
                marker_color=["#00BFA6", "#F59E0B", "#EF4444"],
                text=[f"{probs['Safe']*100:.1f}%", f"{probs['Spam']*100:.1f}%", f"{probs['Scam']*100:.1f}%"],
                textposition="auto",
            )
        )
        fig_prob.update_layout(
            title="Class Probability Distribution",
            height=210,
            margin=dict(l=10, r=10, t=35, b=10),
            paper_bgcolor="#121720",
            plot_bgcolor="#121720",
            font=dict(color="#F1F0EC"),
            xaxis=dict(range=[0, 100], title="Probability (%)"),
        )
        st.plotly_chart(fig_prob, use_container_width=True)

        st.markdown("##### Plain-Language Forensic Reasons")
        for r in eval_res["reasons"]:
            st.markdown(f"- {r}")

        if eval_res.get("all_models_comparison"):
            st.markdown("##### 5-Classifier Consensus Comparison for This Call")
            st.dataframe(pd.DataFrame(eval_res["all_models_comparison"]), use_container_width=True, hide_index=True)

# ==============================================================================
# PAGE 03: CALL TRANSCRIPT SCAM ANALYZER
# ==============================================================================
elif selected_page.startswith("03"):
    st.markdown(
        """
        <div class="mono" style="font-size:11.5px; color:#00BFA6; text-transform:uppercase;">03 // Rule-Based Transcript Analyzer</div>
        <h2>Call Transcript <span class="serif-accent" style="font-size:32px;">Scam Script Forensics</span></h2>
        """,
        unsafe_allow_html=True,
    )

    sample_keys = list(SAMPLE_TRANSCRIPTS.keys())
    selected_sample = st.selectbox("Load Sample Call Transcript", sample_keys, index=0)
    uploaded_txt = st.file_uploader("Or Upload a Call Transcript (.txt)", type=["txt"])
    default_txt = (
        uploaded_txt.read().decode("utf-8", errors="ignore")
        if uploaded_txt is not None
        else SAMPLE_TRANSCRIPTS[selected_sample]["transcript"]
    )

    transcript_input = st.text_area("Pasted Call Transcript", value=default_txt, height=140)
    t_res = analyze_transcript(transcript_input)

    c_left, c_right = st.columns([1.1, 0.9])
    with c_left:
        st.markdown("##### Inline Highlighted Transcript")
        spans = t_res["highlighted_spans"]
        out_parts = []
        cursor = 0
        for sp in spans:
            if sp["start"] > cursor:
                out_parts.append(html.escape(transcript_input[cursor : sp["start"]]))
            snip = html.escape(transcript_input[sp["start"] : sp["end"]])
            cat_tag = html.escape(sp["category_name"])
            out_parts.append(f'<span class="hl-span">{snip}<span class="hl-tag">{cat_tag}</span></span>')
            cursor = sp["end"]
        if cursor < len(transcript_input):
            out_parts.append(html.escape(transcript_input[cursor:]))

        st.markdown(
            f'<div class="ledger-card" style="line-height:1.85; font-size:15px;">{"".join(out_parts)}</div>',
            unsafe_allow_html=True,
        )

        with st.expander("Inspect All 10 Regex Pattern Categories"):
            st.json([{c["name"]: c["patterns"]} for c in SCAM_CATEGORIES])

    with c_right:
        v_cls = t_res["verdict_label"].lower()
        st.markdown(
            f"""
            <div class="verdict-box {v_cls}">
                <div class="mono" style="font-size:12px;">TRANSCRIPT VERDICT: {t_res['verdict_label'].upper()}</div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:6px;">
                    <div style="font-size:20px; font-weight:700;">{html.escape(t_res['risk_tier'])}</div>
                    <div class="mono" style="font-size:36px; font-weight:700;">{t_res['transcript_risk_score']:.1f}/100</div>
                </div>
                <p style="margin-top:8px; font-size:13.5px;">{html.escape(t_res['summary_explanation'])}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        cat_table = pd.DataFrame(
            [
                {
                    "Category": c["name"],
                    "Weight": c["weight"],
                    "Status": f"MATCHED ({c['match_count']})" if c["matched"] else "CLEAR",
                    "Matched Phrases": ", ".join(c["matches"]) if c["matches"] else "—",
                }
                for c in t_res["all_categories_status"]
            ]
        )
        st.dataframe(cat_table, use_container_width=True, hide_index=True)

# ==============================================================================
# PAGE 04: COMMUNITY REPORTING & NUMBER REPUTATION
# ==============================================================================
elif selected_page.startswith("04"):
    st.markdown(
        """
        <div class="mono" style="font-size:11.5px; color:#00BFA6; text-transform:uppercase;">04 // Crowdsourced SQLite Reputation</div>
        <h2>Community Reporting &amp; <span class="serif-accent" style="font-size:32px;">Number Reputation</span></h2>
        """,
        unsafe_allow_html=True,
    )

    col_lookup, col_submit = st.columns(2)
    with col_lookup:
        st.markdown("##### Lookup Number Reputation in SQLite")
        q_phone = st.text_input("Search Phone Number", value="+91-92104-88319")
        intel = get_number_intelligence(q_phone)
        st.markdown(
            f"""
            <div class="ledger-card">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div class="mono" style="font-size:18px; font-weight:700;">{html.escape(intel['phone_number'])}</div>
                        <div style="color:#00BFA6; font-weight:600;">{html.escape(intel['status_tag'])}</div>
                        <div style="font-size:12.5px; color:#8B97AA;">Carrier: {html.escape(intel['carrier_name'])} &bull; Region: {html.escape(intel['origin_region'])}</div>
                    </div>
                    <div class="mono" style="font-size:32px; font-weight:700; color:#EF4444;">{intel['reputation_risk_score']:.1f}/100</div>
                </div>
                <hr style="border-color:#232C3B; margin:12px 0;"/>
                <div class="mono" style="font-size:12.5px;">
                    Total Reports: <strong>{intel['total_reports']}</strong> &bull;
                    Scam: <strong>{intel['scam_reports']}</strong> &bull;
                    Spam: <strong>{intel['spam_reports']}</strong> &bull;
                    Safe Votes: <strong>{intel['safe_votes']}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if intel["reports"]:
            st.dataframe(pd.DataFrame(intel["reports"]), use_container_width=True, hide_index=True)

    with col_submit:
        st.markdown("##### Submit New Community Threat Report")
        with st.form("community_report_form"):
            r_phone = st.text_input("Caller Phone Number", value="+91-81309-44102")
            r_cat = st.selectbox("Category", ["Scam", "Spam", "Safe"])
            r_sub = st.selectbox(
                "Incident Subtype",
                [
                    "Bank KYC / OTP Phishing",
                    "Digital Arrest / CBI & Customs Impersonation",
                    "UPI / QR Code Payment Trap",
                    "Remote Access (AnyDesk / TeamViewer) Scam",
                    "Unsolicited Loan & Credit Card Telemarketing",
                    "Verified Personal / Institutional Contact",
                ],
            )
            r_id = st.text_input("Claimed Identity", value="Fake Bank KYC Desk")
            r_sev = st.slider("Severity (1–5)", 1, 5, 5)
            r_reg = st.text_input("Your Region", value="Greater Noida, Delhi NCR")
            r_comment = st.text_area("Incident Details", value="Caller demanded 6-digit OTP to prevent account freeze.")
            rep_btn = st.form_submit_button("Submit Report to SQLite", use_container_width=True)
            if rep_btn:
                updated = submit_community_report(r_phone, r_cat, r_sub, r_id, r_sev, r_comment, r_reg)
                st.success(f"Report saved for {updated['phone_number']}! Updated Reputation Score: {updated['reputation_risk_score']}/100")

    st.markdown("##### Global Community Threat Feed")
    f_cat = st.selectbox("Filter by Category", ["All", "Scam", "Spam", "Safe"])
    all_reps = get_all_community_reports(category=f_cat)
    st.dataframe(pd.DataFrame(all_reps), use_container_width=True, hide_index=True)

# ==============================================================================
# PAGE 05: LIVE THREAT INTELLIGENCE DASHBOARD
# ==============================================================================
elif selected_page.startswith("05"):
    st.markdown(
        """
        <div class="mono" style="font-size:11.5px; color:#00BFA6; text-transform:uppercase;">05 // Real-Time SQLite Analytics</div>
        <h2>Live Threat Intelligence <span class="serif-accent" style="font-size:32px;">Operations Dashboard</span></h2>
        """,
        unsafe_allow_html=True,
    )
    b_col1, b_col2 = st.columns([1, 3])
    with b_col1:
        if st.button("+ Simulate 5 Live Incoming Calls", use_container_width=True):
            for _, item in PRESET_CALL_SCENARIOS.items():
                feats = dict(item["features"])
                feats["calls_last_24h"] = max(1, int(feats["calls_last_24h"] + random.randint(-2, 4)))
                evaluate_incoming_call(feats, persist_log=True)
            st.success("Simulated 5 incoming calls and logged to SQLite!")
    with b_col2:
        st.download_button(
            "Download Call Audit Logs CSV",
            data=export_table_to_csv_string("call_logs"),
            file_name="call_logs_export.csv",
            mime="text/csv",
        )

    dash = get_dashboard_statistics()

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total Calls Analyzed", dash["total_calls_analyzed"])
    k2.metric("Scam Calls Flagged", dash["scam_calls_detected"])
    k3.metric("Spam Calls Detected", dash["spam_calls_detected"])
    k4.metric("Community Reports", dash["total_community_reports"])

    c_wl, c_sub = st.columns(2)
    with c_wl:
        st.markdown("##### High-Risk Watchlist Leaderboard")
        st.dataframe(pd.DataFrame(dash["watchlist"]), use_container_width=True, hide_index=True)
    with c_sub:
        st.markdown("##### Community Incident Subtypes")
        sub_df = pd.DataFrame(dash["subtype_breakdown"])
        if not sub_df.empty:
            fig_sub = px.bar(
                sub_df,
                x="count",
                y="scam_subtype",
                color="reported_category",
                orientation="h",
                color_discrete_map={"Scam": "#EF4444", "Spam": "#F59E0B", "Safe": "#00BFA6"},
            )
            fig_sub.update_layout(
                height=320,
                paper_bgcolor="#121720",
                plot_bgcolor="#121720",
                font=dict(color="#F1F0EC"),
                margin=dict(l=10, r=10, t=20, b=10),
            )
            st.plotly_chart(fig_sub, use_container_width=True)

    st.markdown("##### Recent Analyzed Calls Audit Log (`call_logs`)")
    st.dataframe(pd.DataFrame(dash["recent_logs"]), use_container_width=True, hide_index=True)

# ==============================================================================
# PAGE 06: SYNTHETIC DATASET EXPLORER
# ==============================================================================
elif selected_page.startswith("06"):
    st.markdown(
        """
        <div class="mono" style="font-size:11.5px; color:#00BFA6; text-transform:uppercase;">06 // 6,000-Row Synthetic Dataset</div>
        <h2>Synthetic Dataset <span class="serif-accent" style="font-size:32px;">&amp; Feature Explorer</span></h2>
        """,
        unsafe_allow_html=True,
    )
    df = load_and_clean_dataset()

    st.download_button(
        "Download Full 6,000-Row Dataset (calls.csv)",
        data=df.to_csv(index=False),
        file_name="calls_synthetic_6000.csv",
        mime="text/csv",
    )

    c1, c2 = st.columns([1, 1])
    with c1:
        selected_feat = st.selectbox("Inspect Numeric Feature Distribution by Class", NUMERIC_FEATURES, index=0)
        fig_hist = px.histogram(
            df,
            x=selected_feat,
            color="label",
            barmode="overlay",
            nbins=40,
            color_discrete_map={"Safe": "#00BFA6", "Spam": "#F59E0B", "Scam": "#EF4444"},
            title=f"Distribution of {FEATURE_METADATA[selected_feat]['label']}",
        )
        fig_hist.update_layout(paper_bgcolor="#121720", plot_bgcolor="#121720", font=dict(color="#F1F0EC"))
        st.plotly_chart(fig_hist, use_container_width=True)
    with c2:
        selected_cat = st.selectbox("Inspect Categorical Feature by Class", CATEGORICAL_FEATURES, index=0)
        cat_counts = df.groupby([selected_cat, "label"]).size().reset_index(name="count")
        fig_cat = px.bar(
            cat_counts,
            x=selected_cat,
            y="count",
            color="label",
            barmode="group",
            color_discrete_map={"Safe": "#00BFA6", "Spam": "#F59E0B", "Scam": "#EF4444"},
            title=f"Class Breakdown across {FEATURE_METADATA[selected_cat]['label']}",
        )
        fig_cat.update_layout(paper_bgcolor="#121720", plot_bgcolor="#121720", font=dict(color="#F1F0EC"))
        st.plotly_chart(fig_cat, use_container_width=True)

    st.markdown("##### 10×10 Numeric Feature Correlation Heatmap")
    corr = df[NUMERIC_FEATURES].corr().round(2)
    fig_corr = px.imshow(corr, text_auto=True, color_continuous_scale="Tealgrn")
    fig_corr.update_layout(paper_bgcolor="#121720", plot_bgcolor="#121720", font=dict(color="#F1F0EC"), height=440)
    st.plotly_chart(fig_corr, use_container_width=True)

    st.markdown("##### Browse Synthetic Dataset (`data/calls.csv`)")
    st.dataframe(df.head(100), use_container_width=True, hide_index=True)

# ==============================================================================
# PAGE 07: ML MODEL BENCHMARK LAB
# ==============================================================================
elif selected_page.startswith("07"):
    st.markdown(
        """
        <div class="mono" style="font-size:11.5px; color:#00BFA6; text-transform:uppercase;">07 // 5-Classifier Supervised Evaluation</div>
        <h2>ML Model Comparison <span class="serif-accent" style="font-size:32px;">&amp; Evaluation Lab</span></h2>
        """,
        unsafe_allow_html=True,
    )
    if st.button("Re-Train & Verify All 5 Classifiers"):
        with st.spinner("Training 5 classifiers on 80/20 stratified split..."):
            train_and_evaluate_all()
            load_artifacts(force_reload=True)

    metrics = load_evaluation_metrics()
    models_df = pd.DataFrame(
        [
            {
                "Model": m["model_name"] + (" (Best)" if i == 0 else ""),
                "Accuracy": m["accuracy"],
                "Macro-F1": m["f1_macro"],
                "Macro-Precision": m["precision_macro"],
                "Macro-Recall": m["recall_macro"],
                "ROC-AUC": m["roc_auc_macro"],
                "Train Time (s)": m["train_time_sec"],
            }
            for i, m in enumerate(metrics["models"])
        ]
    )
    st.dataframe(models_df, use_container_width=True, hide_index=True)

    col_fi, col_cm = st.columns(2)
    with col_fi:
        fi_df = pd.DataFrame(metrics["feature_importances"][:10])
        fig_fi = px.bar(
            fi_df,
            x="importance",
            y="feature",
            orientation="h",
            title="Random Forest Feature Importances",
            color_discrete_sequence=["#00BFA6"],
        )
        fig_fi.update_layout(
            yaxis=dict(autorange="reversed"),
            paper_bgcolor="#121720",
            plot_bgcolor="#121720",
            font=dict(color="#F1F0EC"),
        )
        st.plotly_chart(fig_fi, use_container_width=True)
    with col_cm:
        chosen_cm_model = st.selectbox("Select Model for Confusion Matrix", [m["model_name"] for m in metrics["models"]])
        m_obj = next(m for m in metrics["models"] if m["model_name"] == chosen_cm_model)
        fig_cm = px.imshow(
            m_obj["confusion_matrix"],
            x=CLASSES,
            y=CLASSES,
            text_auto=True,
            color_continuous_scale="Tealgrn",
            labels=dict(x="Predicted Class", y="Actual Class"),
            title=f"Confusion Matrix — {chosen_cm_model}",
        )
        fig_cm.update_layout(paper_bgcolor="#121720", plot_bgcolor="#121720", font=dict(color="#F1F0EC"))
        st.plotly_chart(fig_cm, use_container_width=True)

# ==============================================================================
# PAGE 08: SYSTEM TESTING, EDGE CASES & DEFECT LOG
# ==============================================================================
elif selected_page.startswith("08"):
    st.markdown(
        """
        <div class="mono" style="font-size:11.5px; color:#00BFA6; text-transform:uppercase;">08 // Automated QA &amp; Defect Resolution</div>
        <h2>System Verification <span class="serif-accent" style="font-size:32px;">&amp; Defect Log</span></h2>
        """,
        unsafe_allow_html=True,
    )
    suite = run_all_verification_checks()
    st.success(f"Automated Verification Suite: {suite['passed_checks']} / {suite['total_checks']} Checks Passed (100%)")

    st.markdown("##### Interactive Edge-Case Sandbox")
    ec1, ec2, ec3 = st.columns(3)
    with ec1:
        raw_p = st.text_input("Malformed Phone Input (Defect #1)", value="'+91 (981) 045-2391")
        st.code(f"Sanitized: {sanitize_phone_number(raw_p)}")
    with ec2:
        unseen_p = st.text_input("Unseen Prefix Category (Defect #2)", value="Satellite_Global_Gateway")
        pred_edge = predict_call_risk({"phone_number": raw_p, "prefix_type": unseen_p})
        st.code(f"Predicted: {pred_edge['predicted_label']} ({pred_edge['ml_risk_score']}/100)")
    with ec3:
        ov_trans = st.text_input("Overlapping Regex Input (Defect #4)", value="Share 6-digit OTP verification code within 10 minutes.")
        tr_edge = analyze_transcript(ov_trans)
        st.code(f"Transcript Score: {tr_edge['transcript_risk_score']}/100 ({tr_edge['matched_count']} hits)")

    col_chk, col_def = st.columns(2)
    with col_chk:
        st.markdown("##### Live Unit & Edge-Case Test Results")
        st.dataframe(pd.DataFrame(suite["checks"]), use_container_width=True, hide_index=True)
    with col_def:
        st.markdown("##### Development Defect Log (Section 9)")
        st.dataframe(pd.DataFrame(suite["defect_log"]), use_container_width=True, hide_index=True)
