"""
Streamlit dashboard — full version.
Tabs: Overview · Detections · Users · Anomaly Detection · Threat Events

Run:  streamlit run dashboard/app.py
"""

import os
import sys
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from sqlalchemy import create_engine, text

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///leakdetect.db")
engine       = create_engine(DATABASE_URL)

st.set_page_config(
    page_title="Leak Detection Dashboard",
    page_icon="🔐",
    layout="wide",
)

# ── helpers ─────────────────────────────────────────────────────────────────

SEV_COLORS = {
    "CLEAN":    "#C0DD97",
    "LOW":      "#FAC775",
    "MEDIUM":   "#EF9F27",
    "HIGH":     "#D85A30",
    "CRITICAL": "#E24B4A",
}

@st.cache_data(ttl=30)
def load_data():
    with engine.connect() as conn:
        files      = pd.read_sql("SELECT * FROM scanned_files", conn)
        detections = pd.read_sql("SELECT * FROM detections",    conn)
        events     = pd.read_sql("SELECT * FROM risk_events",   conn)
        users      = pd.read_sql("SELECT * FROM users",         conn)

        # anomaly_results may not exist yet
        try:
            anomalies = pd.read_sql("SELECT * FROM anomaly_results", conn)
        except Exception:
            anomalies = pd.DataFrame()

    # parse datetimes
    for df, col in [(files, "scanned_at"), (detections, "detected_at"),
                     (events, "created_at")]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col])

    return files, detections, events, users, anomalies


def severity_badge(sev: str) -> str:
    colors = {"CLEAN":"🟢","LOW":"🟡","MEDIUM":"🟠","HIGH":"🔴","CRITICAL":"🔴"}
    return f"{colors.get(sev,'⚪')} {sev}"


# ── load ─────────────────────────────────────────────────────────────────────

try:
    files, detections, events, users, anomalies = load_data()
except Exception as e:
    st.error(f"Database error: {e}")
    st.info("Run `python run_demo.py` first to populate the database.")
    st.stop()

# ── header ───────────────────────────────────────────────────────────────────

st.title("🔐 Data Leak Detection & Insider Threat Analytics")

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Files scanned",        len(files))
c2.metric("Total detections",     len(detections))
c3.metric("Alerts",               int(files["alert"].sum()))
c4.metric("Critical files",       len(files[files["severity"] == "CRITICAL"]))
c5.metric("Threat events",        len(events))
c6.metric("Anomalies (ML)",       int(anomalies["is_anomaly"].sum()) if not anomalies.empty else "—")

st.divider()

# ── tabs ─────────────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Overview",
    "🔍 Detections",
    "👤 Users",
    "🤖 Anomaly Detection",
    "🚨 Threat Events",
])


# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — Overview
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Detections over time")
        if not detections.empty:
            trend = (detections
                     .groupby(detections["detected_at"].dt.date)
                     .size()
                     .reset_index(name="count"))
            trend.columns = ["date", "count"]
            fig = px.area(trend, x="date", y="count",
                          color_discrete_sequence=["#534AB7"])
            fig.update_layout(margin=dict(l=0,r=0,t=10,b=0))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No detections yet.")

    with col2:
        st.subheader("Severity breakdown")
        if not files.empty:
            sev = files["severity"].value_counts().reset_index()
            sev.columns = ["severity", "count"]
            fig3 = px.pie(sev, names="severity", values="count",
                          color="severity", color_discrete_map=SEV_COLORS, hole=0.45)
            fig3.update_layout(margin=dict(l=0,r=0,t=10,b=0))
            st.plotly_chart(fig3, use_container_width=True)

    col3, col4 = st.columns(2)

    with col3:
        st.subheader("Most common leak types")
        if not detections.empty:
            tc = detections["pattern_type"].value_counts().reset_index()
            tc.columns = ["type", "count"]
            fig2 = px.bar(tc, x="count", y="type", orientation="h",
                          color="count",
                          color_continuous_scale=["#EEEDFE","#534AB7"])
            fig2.update_layout(margin=dict(l=0,r=0,t=10,b=0), coloraxis_showscale=False)
            st.plotly_chart(fig2, use_container_width=True)

    with col4:
        st.subheader("Risk score distribution")
        if not files.empty:
            fig4 = px.histogram(files[files["risk_score"] > 0],
                                x="risk_score", nbins=20,
                                color_discrete_sequence=["#534AB7"])
            fig4.update_layout(margin=dict(l=0,r=0,t=10,b=0))
            st.plotly_chart(fig4, use_container_width=True)

    st.subheader("⚠️ High-risk files")
    if not files.empty:
        high = (files[files["risk_score"] > 0]
                .sort_values("risk_score", ascending=False)
                [["filename","severity","risk_score","scanned_at","alert","file_type"]]
                .head(30))
        st.dataframe(high, use_container_width=True, hide_index=True)


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — Detections drill-down
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("All detections")

    col_f1, col_f2 = st.columns(2)
    with col_f1:
        sev_filter = st.multiselect(
            "Filter by severity",
            options=["CRITICAL","HIGH","MEDIUM","LOW"],
            default=["CRITICAL","HIGH"],
        )
    with col_f2:
        src_filter = st.multiselect(
            "Filter by source",
            options=["regex","nlp"],
            default=["regex","nlp"],
        )

    filtered = detections.copy()
    if sev_filter:
        filtered = filtered[filtered["severity"].isin(sev_filter)]
    if src_filter:
        filtered = filtered[filtered["source"].isin(src_filter)]

    st.dataframe(
        filtered.sort_values("detected_at", ascending=False)
                [["detected_at","pattern_type","severity","source","context","file_id"]]
                .head(200),
        use_container_width=True, hide_index=True,
    )

    st.subheader("Detections by file type")
    if not detections.empty:
        merged = detections.merge(
            files[["id","file_type"]], left_on="file_id", right_on="id", how="left"
        )
        by_type = merged.groupby(["file_type","pattern_type"]).size().reset_index(name="count")
        fig5 = px.bar(by_type, x="file_type", y="count", color="pattern_type",
                      barmode="stack", color_discrete_sequence=px.colors.qualitative.Vivid)
        st.plotly_chart(fig5, use_container_width=True)


# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — Users
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    if users.empty:
        st.info("No users yet. Create users with:\n```\npython -m security.user_manager add --username alice --department Engineering\n```")
    else:
        st.subheader("User risk scores")
        fig_u = px.bar(
            users.sort_values("risk_score", ascending=True),
            x="risk_score", y="username", orientation="h",
            color="risk_score",
            color_continuous_scale=["#C0DD97","#EF9F27","#E24B4A"],
        )
        fig_u.update_layout(margin=dict(l=0,r=0,t=10,b=0), coloraxis_showscale=False)
        st.plotly_chart(fig_u, use_container_width=True)

        st.dataframe(
            users.sort_values("risk_score", ascending=False)
                 [["username","department","risk_score","violation_count","last_violation"]],
            use_container_width=True, hide_index=True,
        )

        st.subheader("Files per user")
        if not files.empty and "owner_id" in files.columns:
            user_files = (files[files["owner_id"].notna()]
                          .merge(users[["id","username"]], left_on="owner_id", right_on="id", how="left")
                          .groupby("username")
                          .agg(files=("id_x","count"), avg_risk=("risk_score","mean"), alerts=("alert","sum"))
                          .reset_index())
            st.dataframe(user_files, use_container_width=True, hide_index=True)


# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — Anomaly Detection (ML)
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("🤖 Isolation Forest Anomaly Detection")

    col_ml1, col_ml2 = st.columns([2, 1])

    with col_ml2:
        st.markdown("**Train / retrain model**")
        contamination = st.slider(
            "Expected anomaly fraction", 0.01, 0.30, 0.05, step=0.01,
            help="Proportion of files expected to be anomalous"
        )
        if st.button("🚀 Train model now", type="primary"):
            with st.spinner("Training Isolation Forest..."):
                try:
                    from ml.train import main as train_main, load_training_data, ensure_anomaly_table, write_results
                    from ml.anomaly_detector import AnomalyDetector
                    from db.init_db import init as db_init
                    import sqlalchemy

                    eng = sqlalchemy.create_engine(DATABASE_URL)
                    ensure_anomaly_table(eng)
                    df_train = load_training_data(eng)

                    if len(df_train) < 5:
                        st.warning("Need at least 5 scanned files to train.")
                    else:
                        from datetime import datetime
                        detector = AnomalyDetector(contamination=contamination)
                        detector.fit(df_train)
                        is_anom, score = detector.predict(df_train)
                        write_results(eng, df_train, is_anom, score,
                                      model_version=f"iforest-{datetime.utcnow().strftime('%Y%m%d-%H%M')}")
                        detector.save()
                        st.success(f"✅ Model trained! {int(is_anom.sum())} anomalies found.")
                        st.cache_data.clear()
                        st.rerun()
                except Exception as ex:
                    st.error(f"Training failed: {ex}")

        st.markdown("---")
        model_path = "ml/model.pkl"
        if os.path.exists(model_path):
            mtime = os.path.getmtime(model_path)
            import datetime
            st.success(f"Model on disk\n\nLast trained: {datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')}")
        else:
            st.warning("No model trained yet.")

    with col_ml1:
        if anomalies.empty:
            st.info("No anomaly results yet. Train the model using the panel on the right.")
        else:
            merged_anom = anomalies.merge(
                files[["id","filename","risk_score","severity","file_type","scanned_at"]],
                left_on="file_id", right_on="id", how="left",
            )

            n_anom = int(anomalies["is_anomaly"].sum())
            n_norm = len(anomalies) - n_anom

            # Gauge-style metric
            col_a, col_b = st.columns(2)
            col_a.metric("Anomalies detected",  n_anom, delta=None)
            col_b.metric("Normal files",        n_norm, delta=None)

            # Scatter: risk_score vs anomaly_score
            st.markdown("**Risk score vs anomaly score**")
            fig_anom = px.scatter(
                merged_anom,
                x="risk_score",
                y="anomaly_score",
                color=merged_anom["is_anomaly"].map({0:"Normal", 1:"Anomaly"}),
                color_discrete_map={"Normal":"#534AB7","Anomaly":"#E24B4A"},
                hover_data=["filename","severity","file_type"],
                size_max=12,
            )
            fig_anom.add_hline(y=0, line_dash="dot", line_color="gray",
                               annotation_text="anomaly threshold")
            fig_anom.update_layout(margin=dict(l=0,r=0,t=10,b=0), legend_title="")
            st.plotly_chart(fig_anom, use_container_width=True)

            # Anomalous files table
            st.markdown("**Flagged anomalous files**")
            anom_files = (merged_anom[merged_anom["is_anomaly"] == 1]
                          .sort_values("anomaly_score")
                          [["filename","severity","risk_score","anomaly_score","file_type","scored_at"]]
                          )
            if anom_files.empty:
                st.success("No anomalies detected with current model settings.")
            else:
                st.dataframe(anom_files, use_container_width=True, hide_index=True)

            # Score distribution
            st.markdown("**Anomaly score distribution**")
            fig_dist = px.histogram(
                merged_anom, x="anomaly_score", nbins=20,
                color=merged_anom["is_anomaly"].map({0:"Normal",1:"Anomaly"}),
                color_discrete_map={"Normal":"#534AB7","Anomaly":"#E24B4A"},
                barmode="overlay", opacity=0.75,
            )
            fig_dist.add_vline(x=0, line_dash="dot", line_color="gray")
            fig_dist.update_layout(margin=dict(l=0,r=0,t=10,b=0), legend_title="")
            st.plotly_chart(fig_dist, use_container_width=True)


# ════════════════════════════════════════════════════════════════════════════
# TAB 5 — Threat Events
# ════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("Insider threat events")

    if events.empty:
        st.info("No threat events yet. Events are generated when users repeatedly trigger alerts, "
                "access files off-hours, or bulk-scan files.\n\n"
                "Try assigning files to users:\n"
                "```\npython -m security.user_manager add --username alice --department Finance\n"
                "python -m security.user_manager assign --username alice --directory ./data/sample_files\n```"
                "\nThen re-run `python run_demo.py`.")
    else:
        # Summary by event type
        et = events["event_type"].value_counts().reset_index()
        et.columns = ["event_type", "count"]
        fig_et = px.bar(et, x="event_type", y="count",
                        color="event_type",
                        color_discrete_sequence=["#E24B4A","#D85A30","#EF9F27","#634AB7"])
        fig_et.update_layout(margin=dict(l=0,r=0,t=10,b=0), showlegend=False)
        st.plotly_chart(fig_et, use_container_width=True)

        # Timeline
        st.markdown("**Event timeline**")
        timeline = (events.groupby([events["created_at"].dt.date, "event_type"])
                    .size()
                    .reset_index(name="count"))
        timeline.columns = ["date","event_type","count"]
        fig_tl = px.line(timeline, x="date", y="count", color="event_type", markers=True)
        st.plotly_chart(fig_tl, use_container_width=True)

        # Raw table
        display_cols = [c for c in ["event_type","score_delta","created_at","user_id","file_id","metadata"]
                        if c in events.columns]
        st.dataframe(
            events.sort_values("created_at", ascending=False)[display_cols].head(100),
            use_container_width=True, hide_index=True,
        )

st.divider()
st.caption("🔐 Leak Detection Dashboard · Auto-refreshes every 30 s · SQLite backend")
