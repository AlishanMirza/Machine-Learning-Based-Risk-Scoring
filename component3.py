#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# ============================================================
# File: 03_component3_review_app.py
#
# Description:
#   Component 3 — Human-in-the-Loop Governance Finalization
#   Streamlit dashboard for reviewing AI-generated
#   Governance_Action_Packets and producing a permanent,
#   auditable Security_Governance_Report.
#
# Usage:
#   streamlit run 03_component3_review_app.py
#
# Input:
#   outputs/intel_objects/governance_action_packets_v3.jsonl
#
# Output:
#   outputs/audit/security_governance_report.jsonl
#   outputs/audit/security_governance_report.csv
# ============================================================

import json
import csv
from pathlib import Path
from datetime import datetime
import streamlit as st

# ------------------------------------------------------------
# Dynamic project-root detection
# ------------------------------------------------------------
def find_project_root() -> Path:
    """Locate the project root dynamically for macOS, Linux, or Colab."""
    candidates = [
        Path.cwd(),
        Path.home() / "Research" / "AI_GRC_Project",
        Path("/content/AI_GRC_Project"),
    ]
    for c in candidates:
        if (c / "outputs").exists() or (c / "data").exists() or (c / "config").exists():
            return c.resolve()
    return Path.cwd().resolve()


# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------
PROJECT_ROOT = find_project_root()
INTEL_FILE = PROJECT_ROOT / "outputs" / "intel_objects" / "governance_action_packets_v3.jsonl"
AUDIT_DIR = PROJECT_ROOT / "outputs" / "audit"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)
OUT_JSONL = AUDIT_DIR / "security_governance_report.jsonl"
OUT_CSV = AUDIT_DIR / "security_governance_report.csv"

# ------------------------------------------------------------
# Load Governance_Action_Packets
# ------------------------------------------------------------
if not INTEL_FILE.exists():
    st.error(f"Missing required file: {INTEL_FILE}")
    st.stop()

records = [json.loads(l) for l in INTEL_FILE.read_text().splitlines() if l.strip()]
review_needed = [r for r in records if r.get("requires_human", True)]
auto_approved = [r for r in records if not r.get("requires_human", False)]

# ------------------------------------------------------------
# Streamlit configuration
# ------------------------------------------------------------
st.set_page_config(page_title="AI-GRC Governance Review", layout="wide")
st.title("AI-GRC Human-in-the-Loop Governance Review")

# Sidebar
st.sidebar.header("Session Context")
reviewer_email = st.sidebar.text_input("Reviewer Email (required for audit)")
st.sidebar.write(f"Records requiring review: {len(review_needed)}")
st.sidebar.write(f"Auto-approved: {len(auto_approved)}")

# ------------------------------------------------------------
# Review interface
# ------------------------------------------------------------
st.write("### Pending Human Reviews")
review_updates = []

for rec in review_needed:
    with st.expander(f"{rec['intel_id']} — {rec['predicted_severity']} (confidence {rec['confidence']:.2f})"):
        st.write("#### Recommended Actions")
        st.write(rec["recommended_actions"])
        st.caption(rec["explanation"])
        st.write("#### Control Postures (Top 5)")
        st.dataframe([{c["control_id"]: c["posture"] for c in rec["controls"][:5]}])

        decision = st.selectbox(
            "Decision",
            ["Approve", "Override", "Escalate"],
            key=f"dec_{rec['intel_id']}"
        )
        posture = st.selectbox(
            "Final Posture",
            ["Compliant", "At Risk", "Non-Compliant"],
            key=f"pos_{rec['intel_id']}"
        )
        comments = st.text_area("Reviewer Comments", key=f"com_{rec['intel_id']}")
        evidence = st.text_input("Evidence IDs (comma-separated)", key=f"ev_{rec['intel_id']}")

        if st.button(f"Submit Decision for {rec['intel_id']}"):
            update = {
                "intel_id": rec["intel_id"],
                "reviewer": reviewer_email or "anonymous",
                "review_timestamp": datetime.utcnow().isoformat(),
                "decision": decision,
                "final_posture": posture,
                "comments": comments,
                "evidence_links": [e.strip() for e in evidence.split(",") if e.strip()],
            }
            review_updates.append(update)
            st.success(f"Review submitted for {rec['intel_id']}")

# ------------------------------------------------------------
# Finalization and audit report generation
# ------------------------------------------------------------
if st.button("Finalize Governance Report"):
    if not reviewer_email:
        st.warning("Reviewer email is required before finalizing the report.")
        st.stop()

    base = {r["intel_id"]: r for r in records}

    # Merge manual reviews
    for upd in review_updates:
        r = base.get(upd["intel_id"])
        if r:
            r["review"] = upd
            r["timestamp_finalized"] = datetime.utcnow().isoformat()

    # Add auto-approved records
    for r in auto_approved:
        r["review"] = {
            "reviewer": "system@ai-grc",
            "review_timestamp": datetime.utcnow().isoformat(),
            "decision": "Auto-Approved",
            "final_posture": "Compliant",
            "comments": "AI confidence above enterprise threshold.",
        }
        r["timestamp_finalized"] = datetime.utcnow().isoformat()

    # Write JSONL output
    with open(OUT_JSONL, "w", encoding="utf-8") as f:
        for rec in base.values():
            f.write(json.dumps(rec) + "\n")

    # Write CSV summary
    fields = [
        "intel_id",
        "predicted_severity",
        "confidence",
        "requires_human",
        "reviewer",
        "decision",
        "final_posture",
        "comments",
        "timestamp_finalized",
    ]
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        dw = csv.DictWriter(f, fieldnames=fields)
        dw.writeheader()
        for r in base.values():
            rv = r.get("review", {})
            dw.writerow({
                "intel_id": r["intel_id"],
                "predicted_severity": r.get("predicted_severity"),
                "confidence": r.get("confidence"),
                "requires_human": r.get("requires_human"),
                "reviewer": rv.get("reviewer"),
                "decision": rv.get("decision"),
                "final_posture": rv.get("final_posture"),
                "comments": rv.get("comments"),
                "timestamp_finalized": r.get("timestamp_finalized"),
            })

    st.success(f"Final governance audit report written to: {OUT_JSONL}")
    st.info(f"CSV summary available at: {OUT_CSV}")


# In[2]:


get_ipython().system('jupyter nbconvert --to script /Users/jeevandhamala/Research/AI_GRC_Project/component3.ipynb --output /Users/jeevandhamala/Research/AI_GRC_Project/component3.py')


# In[ ]:




