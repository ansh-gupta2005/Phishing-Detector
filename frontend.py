import streamlit as st
import requests
import pandas as pd
import plotly.express as px

BACKEND_URL = "http://127.0.0.1:5000/check_url"
MODEL_METRICS_URL = "http://127.0.0.1:5000/model_metrics"

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded"
)

st.title("🛡️ Phishing URL Detector")
st.markdown("""
Enter one or more URLs below (one per line) to check if they are potentially malicious or safe using ML, heuristics, and Google's Safe Browsing API.
""")

# Show ML model accuracy
try:
    resp = requests.get(MODEL_METRICS_URL, timeout=5)
    if resp.status_code == 200:
        acc = resp.json().get("accuracy")
        if acc is not None:
            st.info(f"🔍 Current ML Model Accuracy: **{acc * 100:.2f}%**")
        else:
            st.warning("⚠️ Model accuracy data not available.")
    else:
        st.warning("⚠️ Could not fetch model accuracy.")
except Exception as e:
    st.warning(f"⚠️ Error fetching model accuracy: {e}")

# Input URLs
urls_text = st.text_area(
    "Enter URLs to check (one URL per line):",
    placeholder="https://example.com\nhttps://test.com",
    height=120
)

if st.button("🔍 Check URLs Safety"):
    if not urls_text.strip():
        st.warning("⚠️ Please enter at least one URL to check.")
    else:
        urls = [u.strip() for u in urls_text.strip().splitlines() if u.strip()]
        st.info(f"Checking {len(urls)} URL(s)...")

        results = []
        threat_type_list = []

        progress_bar = st.progress(0)

        with st.spinner("Checking URLs..."):
            for i, url in enumerate(urls, 1):
                try:
                    response = requests.post(BACKEND_URL, json={"url": url}, timeout=15)
                    if "application/json" in response.headers.get("Content-Type", ""):
                        data = response.json()
                    else:
                        data = {}

                    if response.status_code != 200 or "error" in data:
                        results.append({
                            "URL": url,
                            "Safe": "Error",
                            "Threat Types": data.get("error", "Unknown error"),
                            "Message": data.get("message", ""),
                        })
                    else:
                        is_safe = data.get("is_safe")
                        threat_types = data.get("threat_types", [])
                        message = data.get("message", "")

                        threat_type_list.extend(threat_types)

                        results.append({
                            "URL": url,
                            "Safe": "Safe" if is_safe else "Unsafe",
                            "Threat Types": ", ".join(threat_types) if threat_types else "None",
                            "Message": message
                        })
                except Exception as e:
                    results.append({
                        "URL": url,
                        "Safe": "Error",
                        "Threat Types": str(e),
                        "Message": "",
                    })

                progress_bar.progress(i / len(urls))

        progress_bar.empty()

        # Show results in styled table
        df_results = pd.DataFrame(results)
        st.subheader("🔎 Scan Results")
        st.dataframe(df_results.style.map(
            lambda x: 'background-color: #d4edda; color: #155724;' if x == "Safe" else
                      ('background-color: #f8d7da; color: #721c24;' if x == "Unsafe" else ''),
            subset=["Safe"]
        ), height=300)

        # Threat types distribution
        if threat_type_list:
            st.subheader("📊 Threat Types Distribution")
            threat_counts = pd.Series(threat_type_list).value_counts()
            fig = px.bar(
                threat_counts,
                x=threat_counts.index,
                y=threat_counts.values,
                labels={'x': 'Threat Type', 'y': 'Count'},
                title='Threat Types Distribution',
                color=threat_counts.index,
                color_discrete_sequence=px.colors.qualitative.Bold
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threats detected across scanned URLs.")

        # Summary counts
        safe_count = sum(1 for r in results if r["Safe"] == "Safe")
        unsafe_count = sum(1 for r in results if r["Safe"] == "Unsafe")
        error_count = sum(1 for r in results if r["Safe"] == "Error")

        st.success(f"✅ {safe_count} safe, ⚠️ {unsafe_count} unsafe, ❌ {error_count} errors.")
