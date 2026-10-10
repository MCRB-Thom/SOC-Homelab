#!/usr/bin/env python3
"""
Dashboard de visualisation du pont Wazuh -> Ollama.

Usage:
    streamlit run dashboard.py
"""

import sqlite3
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st

from config import DB_PATH

st.set_page_config(page_title="SOC Dashboard", page_icon="🛡️", layout="wide")


# --------------------------------------------------------------------------
# Chargement des données
# --------------------------------------------------------------------------

@st.cache_data(ttl=30)
def load_data() -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        """
        SELECT alert_timestamp, rule_id, rule_level, rule_description,
               agent_name, severity, summary, recommended_action, processed_at
        FROM classifications
        ORDER BY alert_timestamp DESC
        """,
        conn,
    )
    conn.close()

    if not df.empty:
        df["alert_timestamp"] = pd.to_datetime(df["alert_timestamp"], errors="coerce", utc=True)
        df["processed_at"] = pd.to_datetime(df["processed_at"], errors="coerce", utc=True)

    return df


SEVERITY_ORDER = ["low", "medium", "high", "critical", "unknown"]
SEVERITY_COLORS = {
    "low": "#4CAF50",
    "medium": "#FFC107",
    "high": "#FF5722",
    "critical": "#B71C1C",
    "unknown": "#9E9E9E",
}


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------

st.title("🛡️ SOC Dashboard — Wazuh + Ollama")
st.caption("Classification des alertes de sécurité par LLM local")

df = load_data()

if df.empty:
    st.warning("Aucune donnée trouvée dans la base. Lancer `python bridge.py` pour commencer à classifier des alertes.")
    st.stop()

# --- Barre latérale : filtres ---
st.sidebar.header("Filtres")

severities = st.sidebar.multiselect(
    "Sévérité",
    options=SEVERITY_ORDER,
    default=SEVERITY_ORDER,
)

time_window = st.sidebar.selectbox(
    "Fenêtre temporelle",
    options=["Dernière heure", "Dernières 24h", "Derniers 7 jours", "Tout"],
    index=1,
)

agents = sorted(df["agent_name"].dropna().unique().tolist())
selected_agents = st.sidebar.multiselect("Agent", options=agents, default=agents)

min_level = st.sidebar.slider("Niveau Wazuh minimum", min_value=0, max_value=15, value=0)

# --- Application des filtres ---
filtered = df[df["severity"].isin(severities)]
filtered = filtered[filtered["agent_name"].isin(selected_agents)]
filtered = filtered[filtered["rule_level"] >= min_level]

now = pd.Timestamp.now(tz="UTC")
if time_window == "Dernière heure":
    filtered = filtered[filtered["alert_timestamp"] >= now - timedelta(hours=1)]
elif time_window == "Dernières 24h":
    filtered = filtered[filtered["alert_timestamp"] >= now - timedelta(hours=24)]
elif time_window == "Derniers 7 jours":
    filtered = filtered[filtered["alert_timestamp"] >= now - timedelta(days=7)]

# --- Métriques clés ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total alertes", len(filtered))
col2.metric("Critical + High", int(filtered["severity"].isin(["critical", "high"]).sum()))
col3.metric("Agents distincts", filtered["agent_name"].nunique())
col4.metric(
    "Dernière alerte",
    filtered["alert_timestamp"].max().strftime("%Y-%m-%d %H:%M") if not filtered.empty else "—",
)

st.divider()

# --- Graphiques ---
col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader("Répartition par sévérité")
    severity_counts = (
        filtered["severity"]
        .value_counts()
        .reindex(SEVERITY_ORDER)
        .dropna()
        .reset_index()
    )
    severity_counts.columns = ["severity", "count"]
    fig_pie = px.pie(
        severity_counts,
        names="severity",
        values="count",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        hole=0.4,
    )
    st.plotly_chart(fig_pie, use_container_width=True)

with col_right:
    st.subheader("Top règles déclenchées")
    # sévérité la plus fréquente associée à chaque règle, pour la coloration
    top_rules_severity = (
        filtered.groupby("rule_description")["severity"]
        .agg(lambda s: s.value_counts().idxmax())
        .reset_index()
        .rename(columns={"severity": "dominant_severity"})
    )
    top_rules = (
        filtered["rule_description"]
        .value_counts()
        .head(10)
        .reset_index()
    )
    top_rules.columns = ["rule_description", "count"]
    top_rules = top_rules.merge(top_rules_severity, on="rule_description", how="left")
    fig_bar = px.bar(
        top_rules,
        x="count",
        y="rule_description",
        orientation="h",
        color="dominant_severity",
        color_discrete_map=SEVERITY_COLORS,
    )
    fig_bar.update_layout(yaxis={"categoryorder": "total ascending"}, legend_title_text="Sévérité dominante")
    st.plotly_chart(fig_bar, use_container_width=True)

st.subheader("Timeline des alertes")
timeline = filtered.copy()
timeline["hour"] = timeline["alert_timestamp"].dt.floor("h")
timeline_counts = timeline.groupby(["hour", "severity"]).size().reset_index(name="count")
fig_timeline = px.bar(
    timeline_counts,
    x="hour",
    y="count",
    color="severity",
    color_discrete_map=SEVERITY_COLORS,
    barmode="stack",
)
st.plotly_chart(fig_timeline, use_container_width=True)

st.divider()

# --- Table détaillée ---
st.subheader("Détail des alertes")
st.dataframe(
    filtered[
        [
            "alert_timestamp",
            "severity",
            "rule_level",
            "rule_description",
            "agent_name",
            "summary",
            "recommended_action",
        ]
    ],
    use_container_width=True,
    hide_index=True,
    column_config={
        "alert_timestamp": st.column_config.DatetimeColumn("Horodatage", format="DD/MM/YYYY HH:mm"),
        "severity": "Sévérité",
        "rule_level": "Niveau",
        "rule_description": "Règle",
        "agent_name": "Agent",
        "summary": "Résumé",
        "recommended_action": "Action recommandée",
    },
)
