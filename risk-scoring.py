import streamlit as st
import joblib
import numpy as np
import pandas as pd
from sentence_transformers import SentenceTransformer

# -----------------------------
#Load Models with caching

@st.cache_resource
def load_models():
    # Load your trained pipeline
    pipeline = joblib.load("pipeline.pkl")
    # Load SBERT model
    sbert_model = SentenceTransformer("all-MiniLM-L6-v2")
    return pipeline, sbert_model

pipeline, sbert_model = load_models()

# -----------------------------
#Input Validation Classifier

@st.cache_resource
def load_input_validator():
    # Some known valid/invalid vulnerability samples
    valid_samples = [
        "Remote code execution vulnerability in web server",
        "SQL injection allows attackers to access database",
        "Denial of service via malformed packets",
        "Buffer overflow in authentication module",
    ]
    invalid_samples = [
        "How are you",
        "I love pizza",
        "This is just a test",
        "Hello world",
    ]
    X_valid = sbert_model.encode(valid_samples)
    X_invalid = sbert_model.encode(invalid_samples)
    X_val = np.vstack([X_valid, X_invalid])
    y_val = np.array([1]*len(X_valid) + [0]*len(X_invalid))
    
    from sklearn.linear_model import LogisticRegression
    clf = LogisticRegression()
    clf.fit(X_val, y_val)
    return clf

input_validator = load_input_validator()

def is_valid_vulnerability(desc):
    emb = sbert_model.encode([desc])
    prob = input_validator.predict_proba(emb)[0,1]
    return prob > 0.5, prob

# -----------------------------
# Prediction Function

def predict_severity(description, cwe="UNKNOWN"):
    # Check input validity
    valid, prob_valid = is_valid_vulnerability(description)
    if not valid:
        return "UNKNOWN", prob_valid, "HIGH", False

    # Create features
    emb = sbert_model.encode([description])
    df_numeric = pd.DataFrame(emb)
    novel_features = {
        "CWE": [cwe],
        "desc_length": [len(description)],
    }
    for kw in ["overflow","remote","denial","execute","injection"]:
        novel_features[f"kw_{kw}"] = [int(kw in description.lower())]
    df_novel = pd.DataFrame(novel_features)
    df_pred = pd.concat([df_numeric, df_novel], axis=1)
    
    # Ensure all columns are strings
    df_pred.columns = df_pred.columns.astype(str)

    # Predict
    pred_label = pipeline.predict(df_pred)[0]
    pred_prob = pipeline.predict_proba(df_pred).max()

    # Map probability to risk level
    if pred_prob >= 0.85:
        risk_level = "CRITICAL"
    elif pred_prob >= 0.65:
        risk_level = "HIGH"
    elif pred_prob >= 0.4:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    return pred_label, pred_prob, risk_level, True

# -----------------------------
# Streamlit App

st.title("Vulnerability Risk Scoring ⚡")
desc_input = st.text_area("Enter vulnerability description:")
cwe_input = st.text_input("Enter CWE (optional):")

if st.button("Predict"):
    if not desc_input.strip():
        st.warning("Please enter a vulnerability description.")
    else:
        pred_label, pred_prob, risk_level, valid_flag = predict_severity(desc_input, cwe_input or "UNKNOWN")
        
        if not valid_flag:
            st.warning("⚠️ Input may not be a valid vulnerability description.")
        
        st.subheader("Prediction Results")
        st.write(f"**Predicted Severity:** {pred_label}")
        st.write(f"**Risk Score:** {pred_prob:.2f}")
        st.write(f"**Risk Level:** {risk_level}")
