"""SentinelShield interactive security control center.

Run with: python -m streamlit run dashboard.py
"""

from __future__ import annotations

import json
from collections import Counter

import streamlit as st

from sentinelshield.config import Settings
from sentinelshield.events import EventStore
from sentinelshield.factory import create_service
from sentinelshield.models import HttpRequest


st.set_page_config(page_title="SentinelShield Control Center", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp {background:#07111f}.block-container{max-width:1240px;padding-top:2rem}
.hero{background:linear-gradient(120deg,#0b1f38,#0e3b59 52%,#0f766e);border:1px solid #4d91ae;border-radius:22px;padding:2rem 2.25rem;margin-bottom:1.35rem;box-shadow:0 20px 55px #00000055}
.eyebrow{color:#7dd3fc;font-size:.78rem;font-weight:700;letter-spacing:.12em}.hero h1{color:#f8fafc;font-size:2.25rem;margin:.3rem 0}.hero p,.section-note{color:#cbd5e1;margin:0}
[data-testid="stMetric"]{background:linear-gradient(145deg,#101f33,#0b1728);border:1px solid #334155;border-radius:15px;padding:.75rem 1rem}
div[data-testid="stForm"]{background:#0c1828;border:1px solid #24546e;border-radius:16px;padding:.8rem 1rem .3rem}
.stButton>button,.stFormSubmitButton>button{background:linear-gradient(90deg,#0ea5e9,#14b8a6);color:#fff;border:0;border-radius:9px;font-weight:700}
</style>
<div class="hero"><div class="eyebrow">EDUCATIONAL WEB SECURITY OPERATIONS</div><h1>🛡️ SentinelShield Control Center</h1><p>Inspect requests, trace explainable detections, monitor security events, and verify the local audit trail from one focused workspace.</p></div>
""", unsafe_allow_html=True)

settings = Settings.from_environment()
store = EventStore(settings.database_path)
if "sentinelshield_service" not in st.session_state:
    st.session_state.sentinelshield_service = create_service(settings)
service = st.session_state.sentinelshield_service

inspector_tab, analytics_tab, audit_tab = st.tabs(["⚡ Live Inspector", "📊 Event Analytics", "🔒 Audit & Evidence"])

with inspector_tab:
    st.subheader("Inspect a request in real time")
    st.markdown("<p class='section-note'>Use safe local demonstration data only. Every submission is inspected and saved as a security event.</p>", unsafe_allow_html=True)
    presets = {
        "Normal search": ("GET", "/search", '{"q": "campus map"}', ""),
        "SQL injection indicator": ("GET", "/products", '{"id": "7 OR 1=1"}', ""),
        "XSS indicator": ("POST", "/feedback", "{}", "<script>demo()</script>"),
        "Directory traversal indicator": ("GET", "/download", '{"file": "../../notes.txt"}', ""),
        "Sensitive path probe": ("GET", "/.env", "{}", ""),
    }
    preset = st.selectbox("Quick demonstration preset", list(presets))
    default_method, default_path, default_query, default_body = presets[preset]
    with st.form("request_inspector"):
        left, right = st.columns([1, 2])
        method = left.selectbox("Method", ["GET", "POST", "PUT", "DELETE"], index=["GET", "POST", "PUT", "DELETE"].index(default_method))
        source_ip = right.text_input("Source IP", value="198.51.100.10")
        path = st.text_input("Request path", value=default_path)
        query_text = st.text_area("Query parameters (JSON)", value=default_query, height=90)
        headers_text = st.text_area("Headers (JSON)", value="{}", height=75)
        body = st.text_area("Request body", value=default_body, height=105)
        submitted = st.form_submit_button("Inspect and record request", type="primary", use_container_width=True)
    if submitted:
        try:
            query, headers = json.loads(query_text), json.loads(headers_text)
            if not isinstance(query, dict) or not isinstance(headers, dict):
                raise ValueError("Query parameters and headers must both be JSON objects.")
            if not all(isinstance(k, str) and isinstance(v, str) for k, v in {**query, **headers}.items()):
                raise ValueError("Query and header keys and values must be text.")
            event_id, verdict = service.inspect_and_record(HttpRequest(method, path, query=query, headers=headers, body=body, source_ip=source_ip))
            st.session_state.last_inspection = {"event_id": event_id, "request_path": path, **verdict.to_dict()}
            st.rerun()
        except (json.JSONDecodeError, ValueError) as error:
            st.error(f"Request input was not valid: {error}")
    if "last_inspection" in st.session_state:
        last = st.session_state.last_inspection
        message = f"Event #{last['event_id']} • {last['request_path']}"
        (st.error if last["decision"] == "block" else st.success)(f"Request {last['decision']} • {message}")
        st.json(last)

with analytics_tab:
    events = store.recent_events(limit=100)
    if not events:
        st.info("No events yet. Use the Live Inspector or run the safe simulator to populate this view.")
    else:
        counts = Counter(str(event["decision"]) for event in events)
        integrity = store.verify_integrity()
        a, b, c, d = st.columns(4)
        a.metric("Recorded events", len(events)); b.metric("Blocked events", counts["block"])
        c.metric("Block rate", f"{counts['block'] / len(events) * 100:.1f}%")
        d.metric("Audit chain", "Valid" if integrity.valid else "Check required")
        left, right = st.columns(2)
        with left:
            st.subheader("Decision summary")
            st.bar_chart([{"decision": "Allowed", "events": counts["allow"]}, {"decision": "Blocked", "events": counts["block"]}], x="decision", y="events")
        categories = Counter(finding["category"] for event in events for finding in event["findings"])
        with right:
            st.subheader("Detection categories")
            if categories:
                st.bar_chart([{"category": name, "findings": value} for name, value in categories.most_common()], x="category", y="findings")
            else:
                st.caption("No rule findings have been recorded yet.")
        st.subheader("Event explorer")
        one, two = st.columns(2)
        decision_filter = one.selectbox("Decision", ["All", "Blocked only", "Allowed only"])
        category_filter = two.multiselect("Detection category", sorted(categories))
        filtered = events
        if decision_filter == "Blocked only": filtered = [event for event in filtered if event["decision"] == "block"]
        if decision_filter == "Allowed only": filtered = [event for event in filtered if event["decision"] == "allow"]
        if category_filter: filtered = [event for event in filtered if any(finding["category"] in category_filter for finding in event["findings"])]
        rows = [{"Event": event["id"], "Time (UTC)": event["recorded_at"], "Method": event["method"], "Path": event["path"], "Decision": event["decision"].upper(), "Findings": len(event["findings"]), "Categories": ", ".join(f["category"] for f in event["findings"]) or "—"} for event in filtered]
        st.dataframe(rows, use_container_width=True, hide_index=True)
        for event in filtered[:10]:
            with st.expander(f"Event #{event['id']} • {event['decision'].upper()} • {event['path']}"):
                st.write(event["reason"]); st.json(event["findings"] or {"findings": "No configured attack indicators matched."})

with audit_tab:
    integrity = store.verify_integrity()
    st.subheader("Audit-trail verification")
    st.markdown("<p class='section-note'>New events link to the previous event through SHA-256. This improves local tamper visibility but is not immutable logging.</p>", unsafe_allow_html=True)
    a, b, c = st.columns(3)
    a.metric("Integrity status", "Valid" if integrity.valid else "Invalid")
    b.metric("Chained events checked", integrity.checked_events)
    c.metric("Legacy events", integrity.legacy_events)
    (st.success if integrity.valid else st.error)("The available chained history verifies successfully." if integrity.valid else f"Verification failed at event #{integrity.first_invalid_event_id}.")
    st.divider()
    left, right = st.columns(2)
    with left:
        st.subheader("Evidence export"); st.code("python -m sentinelshield export", language="powershell")
        st.caption("Exports recent events, decisions, categories, severities, and event hashes to CSV.")
    with right:
        st.subheader("Independent verification"); st.code("python -m sentinelshield verify", language="powershell")
        st.caption("Runs the same audit-chain verification from the terminal.")
