#!/usr/bin/env python3

import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
import streamlit as st
from scipy.sparse import hstack, csr_matrix

import shap

from 2_governance_engine import AI_Risk_Intel, GRCEngine, Governance_Action_Packet, packet_to_log_dict, _highest_criticality

# configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ARTIFACT_DIR_DEFAULT = Path("artifacts")
POLICY_PATH = Path("mock_data") / "policy_ruleset.json"
ASSET_DB_PATH = Path("mock_data") / "asset_database.json"


# ---------------------------
# Cached resource loaders
# ---------------------------
@st.cache_resource
def load_artifacts(artifact_dir: str = str(ARTIFACT_DIR_DEFAULT)):
    art = Path(artifact_dir)
    artifacts = {}
    tfidf_pipeline = None
    sbert_wrapper = None
    calibrated = None
    metadata = None
    explainer = None
    explainer_bg = None
    # Load TF-IDF pipeline
    try:
        tfidf_pipeline = joblib.load(art / "tfidf_pipeline.pkl")
    except Exception as e:
        st.warning("tfidf_pipeline.pkl not found or failed to load: %s", e)
        tfidf_pipeline = None
    try:
        sbert_wrapper = joblib.load(art / "sbert_wrapper_meta.pkl")
        # this returns meta dict saved by SentenceTransformerWrapper.save; but our wrapper has load method
        # If load returns dict, convert wrapper object
        if isinstance(sbert_wrapper, dict):
            from 1_ml_pipeline import SentenceTransformerWrapper
            sbert_wrapper = SentenceTransformerWrapper.load(art / "sbert_wrapper_meta.pkl")
    except Exception as e:
        st.warning("sbert_wrapper_meta.pkl not found or failed to load: %s", e)
        sbert_wrapper = None
    try:
        calibrated = joblib.load(art / "calibrated_classifier.pkl")
    except Exception as e:
        st.warning("calibrated_classifier.pkl not found or failed to load: %s", e)
        calibrated = None
    try:
        with open(art / "metadata.json", "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except Exception as e:
        st.warning("metadata.json not found or failed to load: %s", e)
        metadata = None

    # SHAP explainer (may not be picklable)
    try:
        explainer = joblib.load(art / "grc_explainer.pkl")
    except Exception:
        # fallback: load background npz
        try:
            arr = np.load(art / "explainer_bg.npz")
            explainer_bg = arr["X_bg"]
        except Exception as e:
            logger.warning("No SHAP explainer or background found: %s", e)
            explainer_bg = None

    artifacts["tfidf_pipeline"] = tfidf_pipeline
    artifacts["sbert_wrapper"] = sbert_wrapper
    artifacts["calibrated"] = calibrated
    artifacts["metadata"] = metadata
    artifacts["explainer"] = explainer
    artifacts["explainer_bg"] = explainer_bg
    return artifacts


# ---------------------------
# Utility transforms
# ---------------------------
def prepare_features_for_instance(tfidf_pipeline: dict, sbert_wrapper, description: str, cwe: str, cpes: List[str]):
    """
    Transforms a single instance into combined feature matrix compatible with the trained model.
    Returns (X_combined (csr_matrix), feature_info dict)
    """
    # handle missing pipeline pieces
    if tfidf_pipeline is None or sbert_wrapper is None:
        raise RuntimeError("TF-IDF pipeline or SBERT wrapper not loaded.")

    # Build single-row DataFrame
    df = pd.DataFrame([{"description": description, "cwe": cwe, "cpes": cpes}])
    # Use pipeline transform
    X_desc, X_cwe, X_cpe, X_sbert = tfidf_pipeline["transform"](df)
    X_combined = hstack([X_desc, X_cwe, X_cpe, csr_matrix(X_sbert)], format="csr")
    return X_combined


def get_prediction_and_explanation(calibrated_model, X_combined_csr, artifacts, nsamples_shap: int = 100) -> (str, Dict[str, float], Dict[str, float]):
    """
    Returns predicted class label, prediction proba dict, and key_features dict (top shap values).
    """
    # predict proba
    try:
        # if input is sparse, convert as needed
        X_arr = X_combined_csr.toarray()
    except Exception:
        X_arr = X_combined_csr

    probs = calibrated_model.predict_proba(X_arr)
    classes = list(calibrated_model.classes_)
    proba_dict = {classes[i]: float(probs[0, i]) for i in range(len(classes))}
    pred_idx = int(np.argmax(probs[0]))
    pred_class = classes[pred_idx]
    confidence = float(probs[0, pred_idx])

    key_features = {}
    # SHAP explanation
    explainer = artifacts.get("explainer")
    explainer_bg = artifacts.get("explainer_bg")
    try:
        if explainer is not None:
            shap_values = explainer.shap_values(X_arr, nsamples=nsamples_shap)
            # shap_values is a list of arrays (one per class)
            class_shap = shap_values[pred_idx]
            # get top features by absolute shap value
            feat_idx = np.argsort(np.abs(class_shap[0]))[::-1][:10]
            # We don't have feature names mapping easily; just use indices as keys
            key_features = {f"f{int(i)}": float(class_shap[0, int(i)]) for i in feat_idx[:5]}
        elif explainer_bg is not None:
            # Attempt to reconstruct KernelExplainer quickly
            def predict_fn(x):
                return calibrated_model.predict_proba(x)

            # Build a lightweight KernelExplainer (may be slower)
            expl = shap.KernelExplainer(predict_fn, explainer_bg)
            shap_values = expl.shap_values(X_arr, nsamples=nsamples_shap)
            class_shap = shap_values[pred_idx]
            feat_idx = np.argsort(np.abs(class_shap[0]))[::-1][:10]
            key_features = {f"f{int(i)}": float(class_shap[0, int(i)]) for i in feat_idx[:5]}
        else:
            key_features = {}
    except Exception as e:
        logger.warning("SHAP explanation failed: %s", e)
        key_features = {}

    return pred_class, confidence, proba_dict, key_features


# ---------------------------
# Session state initialization
# ---------------------------
def init_session_state():
    if "review_queue" not in st.session_state:
        st.session_state["review_queue"] = []  # list of dicts: {packet, status}
    if "audit_log" not in st.session_state:
        st.session_state["audit_log"] = []  # list of log entries (dict)
    if "artifacts" not in st.session_state:
        try:
            st.session_state["artifacts"] = load_artifacts()
        except Exception as e:
            st.warning("Error loading artifacts: %s", e)
            st.session_state["artifacts"] = {}


# ---------------------------
# run_ml_pipeline helper
# ---------------------------
def run_ml_pipeline_instance(cve_id: str, description: str, cwe: str, cpe_list: List[str], artifacts: dict, metadata: dict, engine: GRCEngine):
    """
    Runs feature transforms, prediction, SHAP explanation, builds AI_Risk_Intel and Governance_Action_Packet.
    """
    tfidf_pipeline = artifacts.get("tfidf_pipeline")
    sbert_wrapper = artifacts.get("sbert_wrapper")
    calibrated = artifacts.get("calibrated")
    if tfidf_pipeline is None or sbert_wrapper is None or calibrated is None:
        raise RuntimeError("Missing artifacts. Make sure pipeline artifacts are present in artifacts/ and loaded.")

    X_combined = prepare_features_for_instance(tfidf_pipeline, sbert_wrapper, description, cwe, cpe_list)
    pred_class, confidence, proba_dict, key_features = get_prediction_and_explanation(calibrated, X_combined, artifacts, nsamples_shap=50)

    model_version = metadata.get("model_version", "unknown") if metadata else "unknown"
    intel = AI_Risk_Intel(
        cve_id=cve_id,
        predicted_severity=pred_class,
        confidence=confidence,
        prediction_proba=proba_dict,
        key_features=key_features,
        model_version=model_version,
        timestamp=datetime_now_iso(),
    )
    packet = engine.generate_governance_packet(intel, cpe_list)
    return intel, packet


# ---------------------------
# Utility: timestamp
# ---------------------------
def datetime_now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ---------------------------
# App pages
# ---------------------------
def page_ingest(artifacts, metadata, engine: GRCEngine):
    st.header("Ingest & Evaluate Vulnerability Intelligence")
    with st.form("ingest_form"):
        cve_id = st.text_input("CVE ID (optional)", value="")
        description = st.text_area("Vulnerability Description", height=200, value="")
        cwe = st.text_input("CWE (optional)", value="")
        cpes_text = st.text_area("CPEs (comma-separated)", height=80, value="")
        submit = st.form_submit_button("Evaluate")

    if submit:
        if not description.strip():
            st.warning("Please provide a description to evaluate.")
            return
        cpe_list = [c.strip() for c in cpes_text.split(",") if c.strip()]
        try:
            intel, packet = run_ml_pipeline_instance(
                cve_id=cve_id or "<manual-input>",
                description=description,
                cwe=cwe,
                cpe_list=cpe_list,
                artifacts=artifacts,
                metadata=metadata,
                engine=engine,
            )
        except Exception as e:
            st.error("Failed to run pipeline: %s" % e)
            return

        st.subheader("AI Risk Intel")
        st.json(asdict(intel))
        st.subheader("Governance Action Packet (provisional)")
        st.json(asdict(packet))

        # Append provisional entry to audit log (status pending)
        log_entry = packet_to_log_dict(packet)
        log_entry.update({"status": "pending", "ingested_at": datetime_now_iso()})
        st.session_state["audit_log"].append(log_entry)

        if packet.requires_human:
            st.info("This packet requires human review and has been added to the Review Queue.")
            st.session_state["review_queue"].append(log_entry)
        else:
            st.success("No mandatory human review required. Packet added to audit log.")


def page_review_queue(engine: GRCEngine):
    st.header("Review Queue (Human-in-the-Loop)")
    queue = st.session_state.get("review_queue", [])
    if not queue:
        st.info("No items in the review queue.")
        return

    for idx, entry in enumerate(list(queue)):  # iterate over copy because we may mutate
        with st.expander(f"{entry.get('cve_id')} — {entry.get('intel', {}).get('predicted_severity')} — status: {entry.get('status', 'pending')}"):
            st.markdown("**Recommended Action:**")
            st.write(entry.get("recommended_action"))
            st.markdown("**Explanation:**")
            st.write(entry.get("explanation"))
            st.markdown("**Key features:**")
            st.write(entry.get("intel", {}).get("key_features", {}))
            st.markdown("---")
            reviewer = st.text_input(f"Reviewer name (item {idx})", value="", key=f"rev_name_{idx}")
            decision = st.selectbox(f"Decision for item {idx}", ["Approve", "Override", "Reject"], key=f"decision_{idx}")
            justification = st.text_area(f"Justification (optional) for item {idx}", key=f"just_{idx}", height=80)
            if st.button(f"Submit decision for item {idx}", key=f"submit_{idx}"):
                # finalize
                final_status = decision.lower()
                log_entry = dict(entry)
                log_entry["status"] = final_status
                log_entry["reviewer"] = reviewer or "unknown"
                log_entry["final_decision"] = decision
                log_entry["justification"] = justification
                log_entry["reviewed_at"] = datetime_now_iso()
                st.session_state["audit_log"].append(log_entry)
                # remove from queue
                st.session_state["review_queue"].pop(idx)
                st.success(f"Recorded decision '{decision}' by {reviewer}. Removed from queue.")
                st.experimental_rerun()


def page_audit_log():
    st.header("Audit Log")
    audit = st.session_state.get("audit_log", [])
    if not audit:
        st.info("Audit log is empty.")
        return
    df = pd.DataFrame(audit)
    # reorder columns for clarity
    cols = ["cve_id", "intel", "predicted_severity", "status", "reviewer", "final_decision", "justification", "ingested_at", "reviewed_at", "timestamp"]
    # transform 'intel' column to simpler items
    if "intel" in df.columns:
        df["predicted_severity"] = df["intel"].apply(lambda x: x.get("predicted_severity") if isinstance(x, dict) else None)
        df["confidence"] = df["intel"].apply(lambda x: x.get("confidence") if isinstance(x, dict) else None)
        df["key_features"] = df["intel"].apply(lambda x: x.get("key_features") if isinstance(x, dict) else None)
    # show table
    st.dataframe(df.sort_values(by=["ingested_at"], ascending=False).reset_index(drop=True))

    # download button
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download audit log CSV", csv, file_name="audit_log.csv", mime="text/csv")
    # optional: persist audit log to disk
    if st.button("Save audit log to disk (audit_log.json)"):
        Path("audit_log.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
        st.success("Saved audit_log.json")


# ---------------------------
# App main
# ---------------------------
def main():
    st.set_page_config(page_title="AI Governance Assistant - VulZoo", layout="wide")
    st.title("AI-driven Vulnerability Governance Assistant (Prototype)")
    init_session_state()
    artifacts = st.session_state["artifacts"]
    metadata = artifacts.get("metadata", {})
    calibrated = artifacts.get("calibrated")
    engine = GRCEngine(policy_ruleset_path=str(POLICY_PATH), asset_db_path=str(ASSET_DB_PATH))

    if calibrated is None:
        st.warning("Calibrated classifier not loaded. Please run the training script (1_ml_pipeline.py) and ensure artifacts are in ./artifacts.")
    page = st.sidebar.radio("Choose page", ["Ingest & Evaluate", "Review Queue", "Audit Log"])

    if page == "Ingest & Evaluate":
        page_ingest(artifacts, metadata, engine)
    elif page == "Review Queue":
        page_review_queue(engine)
    elif page == "Audit Log":
        page_audit_log()
    else:
        st.info("Select a page on the left.")


if __name__ == "__main__":
    main()