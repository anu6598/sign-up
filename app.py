import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

st.set_page_config(page_title="360° Attack Detection", layout="wide")
st.title("🚨 360° API Attack Detection System")
st.write("Upload your log file (1-day data) and detect suspicious activity across Web, iOS, and Android platforms.")

uploaded_file = st.file_uploader("📁 Upload 1-Day API Log CSV", type=["csv"])

@st.cache_data(show_spinner=False)
def read_data(file):
    df = pd.read_csv(file)
    df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
    df['minute'] = df['start_time'].dt.floor('min')
    df['platform'] = df['dr_platform'].fillna('web')
    return df

def detect_brute_force(df):
    brute_df = df[df['request_path'].str.contains("login", case=False, na=False)]
    grouped = brute_df.groupby(['x_real_ip', 'minute']).size().reset_index(name='count')
    brute_ips = grouped[grouped['count'] > 5]['x_real_ip'].unique()
    return df[df['x_real_ip'].isin(brute_ips)]

def detect_vpn_geo(df):
    geo = df.groupby('dr_uid')['x_country_code'].nunique().reset_index()
    flagged = geo[geo['x_country_code'] > 2]['dr_uid']
    return df[df['dr_uid'].isin(flagged)]

def detect_bots(df):
    suspicious_ua = df['user_agent'].str.contains("bot|curl|python|scrapy|wget", case=False, na=False)
    low_duration = df['duration'].astype(float) < 0.3
    return df[suspicious_ua | low_duration]

def detect_ddos(df):
    volume = df.groupby(['x_real_ip', 'minute']).size().reset_index(name='count')
    high_vol_ips = volume[volume['count'] > 10]['x_real_ip'].unique()
    return df[df['x_real_ip'].isin(high_vol_ips)]

def summarize_detection(name, df, platform_col='platform'):
    summary = df.groupby(platform_col).size().reset_index(name='Suspicious Requests')
    summary['attack_type'] = name
    return summary

def user_ip_summary(df, name):
    if 'dr_uid' not in df.columns:
        df['dr_uid'] = "unknown"
    return (
        df.groupby('x_real_ip')['dr_uid']
        .nunique()
        .reset_index(name='Unique Users')
        .sort_values('Unique Users', ascending=False)
        .assign(attack_type=name)
    )

def extract_features_for_model(df):
    df['request_path_len'] = df['request_path'].astype(str).str.len()
    df['ua_len'] = df['user_agent'].astype(str).str.len()
    df['duration'] = pd.to_numeric(df['duration'], errors='coerce').fillna(0)

    # Number of requests per IP
    req_per_ip = df.groupby('x_real_ip').size().rename('request_count').reset_index()
    df = df.merge(req_per_ip, on='x_real_ip', how='left')

    features = df[[
        'duration',
        'request_path_len',
        'ua_len',
        'request_count'
    ]].fillna(0)

    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    return features_scaled, df

def train_isolation_forest(X, contamination=0.02):
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(X)
    return model

if uploaded_file:
    with st.spinner("Reading file..."):
        df = read_data(uploaded_file)
    st.success("✅ File loaded successfully!")

    st.subheader("🔍 Sample of Uploaded Data")
    st.dataframe(df.head(20))

    if st.button("🚨 Run Attack Detection"):
        with st.spinner("Detecting attack patterns..."):
            brute_df = detect_brute_force(df)
            vpn_df = detect_vpn_geo(df)
            bot_df = detect_bots(df)
            ddos_df = detect_ddos(df)

            attack_summary = pd.concat([
                summarize_detection("Brute Force", brute_df),
                summarize_detection("VPN/Geo Switch", vpn_df),
                summarize_detection("Bot-like", bot_df),
                summarize_detection("DDoS", ddos_df)
            ])

            user_ip_breakdown = pd.concat([
                user_ip_summary(brute_df, "Brute Force"),
                user_ip_summary(vpn_df, "VPN/Geo Switch"),
                user_ip_summary(bot_df, "Bot-like"),
                user_ip_summary(ddos_df, "DDoS")
            ])

        st.success("✅ Detection completed!")

        st.subheader("📊 Attack Summary by Platform")
        st.dataframe(attack_summary)

        if not attack_summary.empty:
            fig = px.bar(
                attack_summary,
                x='platform',
                y='Suspicious Requests',
                color='attack_type',
                barmode='group',
                title="Threat Type Distribution by Platform"
            )
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("👥 Unique Users per IP in Attack Types")
        st.dataframe(user_ip_breakdown)

        for label, df_attack in zip(
            ["🔐 Brute Force", "🕵️ VPN/Geo Switch", "🤖 Bot-like", "🌊 DDoS"],
            [brute_df, vpn_df, bot_df, ddos_df]
        ):
            st.subheader(label)

            if not df_attack.empty:
                st.dataframe(df_attack[['start_time', 'x_real_ip', 'request_path', 'dr_uid']].head(10))

                chart_data = df_attack.groupby('minute').size().reset_index(name='Request Count')
                fig = px.line(chart_data, x='minute', y='Request Count', title=f"{label} Over Time")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info(f"No suspicious activity detected for {label}.")

    # 👇 ML-based Anomaly Detection
    st.subheader("🤖 ML-based Anomaly Detection (Isolation Forest)")
    with st.spinner("Extracting features and training Isolation Forest model..."):
        X_scaled, df = extract_features_for_model(df)
        model = train_isolation_forest(X_scaled)
        df['anomaly_score'] = model.decision_function(X_scaled)
        df['is_anomaly'] = model.predict(X_scaled)

    st.subheader("🚩 Anomalous Requests (Predicted by ML Model)")
    anomaly_df = df[df['is_anomaly'] == -1]
    st.dataframe(anomaly_df[['start_time', 'x_real_ip', 'dr_uid', 'request_path', 'duration', 'user_agent']].head(20))

    st.subheader("📉 Anomaly Score Distribution")
    fig = px.histogram(df, x='anomaly_score', nbins=50, title="Anomaly Score Distribution (Lower = More Suspicious)")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("🕵️ Top Suspicious IPs (by ML Prediction)")
    top_ips = anomaly_df['x_real_ip'].value_counts().head(10).reset_index()
    top_ips.columns = ['IP Address', 'Suspicious Request Count']
    st.dataframe(top_ips)
