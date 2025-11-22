# AI-assisted Governance, Risk & Compliance (GRC) engine integrating CVE intelligence, ML-based severity prediction, policy alignment, and human-in-the-loop governance.

## Overview
This system converts raw CVE data into structured, explainable, and governance-ready intelligence. It integrates AI risk estimation (SBERT + LightGBM), NIST/enterprise policy alignment, asset criticality, and a Streamlit-based human-review portal. The output is a complete Security Governance Report suitable for SOC workflows, audit trails, and compliance documentation.

The full pipeline is implemented in:  
**GRC_Implementation_final.ipynb**

---

## Research Objectives
- Transform raw vulnerability intelligence into structured, explainable risk insights.  
- Integrate machine learning predictions with governance policies to produce actionable GRC decisions.  
- Ensure human-in-the-loop validation for high-risk or ambiguous cases.  
- Maintain auditable and traceable outputs for enterprise compliance.

---

## Research Gap
- Most existing tools output only severity labels or CVSS scores without aligning to governance policy or control posture.  
- Few prototypes create explainable, governance-ready artifacts.  
- End-to-end integration (CVE ingestion → ML → GRC mapping → human review → governance report) is largely missing from industry and academic literature.

---

## Key Goals
- Generate calibrated **AI_Risk_Intel** objects enriched with text embeddings, CVE metadata, model probabilities, and explainability fields.  
- Convert predictions into **Governance_Action_Packets** using crosswalks between ML risk, NIST SP 800-53 controls, enterprise policies, and asset criticality.  
- Route high-risk cases to human analysts and record the final decisions.  
- Produce a complete **Security_Governance_Report** for audit and compliance validation.

---

## Methodology

### **Data Ingestion**
- Download CVE records from the NVD mirror Espressif:  
  https://github.com/espressif/esp-nvd-mirror  
- Normalize structure into: description, CWE, CPE, vendors/products, CVSS vectors, publish timestamps.

### **Feature Engineering**
- SBERT text embeddings (SentenceTransformers + PyTorch).  
- CVSS score vectors (8 dimensions).  
- CWE indicators and tokenized vendor/product keywords.  
- Description length and asset criticality (from enterprise catalog).  
- Combined into a model-ready numerical feature matrix.

### **Machine Learning**
- Random Forest, XGBoost, and LightGBM evaluated; **LightGBM selected** as the primary production model.  
- Class imbalance handled using **SMOTE and class-weighting**.  
- Probability calibration via **CalibratedClassifierCV**.  
- Evaluation includes Accuracy, F1, confusion matrix, and per-class precision/recall.

### **Governance Mapping**
Maps AI predictions to governance control frameworks:
- NIST SP 800-53 Rev5 controls  
- Enterprise governance catalogs  
- Asset criticality  

Each **Governance_Action_Packet** includes:
- Required controls  
- Affected assets  
- Recommended governance actions  
- Risk explanations  
- Human-review requirement flag  

### **Human-in-the-Loop**
- Streamlit interface displays each Governance_Action_Packet.  
- Analysts can **Approve**, **Override**, or **Reject**.  
- Decisions are merged into the final Security_Governance_Report.

### **Web UI**
- Built with Streamlit (`component3_review_app.py`).  
- Includes filtering, packet inspection, governance workflow, and CSV/JSONL export.  
- In Colab, Cloudflare tunnel allows secure public access.

---

## Expected Contributions
- A complete, reproducible prototype for AI-assisted security governance.  
- Explainable ML severity predictions calibrated for GRC workflows.  
- Formalized governance objects (AI_Risk_Intel & Governance_Action_Packet).  
- Human-in-the-loop risk validation workflow.  
- Enterprise-ready **Security_Governance_Report** suitable for audits.

---

## Dataset

The dataset was constructed from real-world vulnerability data sourced from the National Vulnerability Database (NVD).  
Access was facilitated through the public GitHub mirror maintained by Espressif:  
https://github.com/espressif/esp-nvd-mirror

The dataset includes CVEs published between **2020 and 2025**.

Fields extracted include:  
- Description  
- CWE  
- CVSS Score  
- Official Severity rating (target label)

The final dataset was cleaned and deduplicated for model validity.

---

## Run Application

### **1. Run in Google Colab**
- Open GRC_Implementation_final.ipynb inside Google Colab.
 #### 1.1 Setup Project Folders
 #### 1.2 Download CVE Dataset
 #### 1.3 Generate AI_Risk_Intel
 #### 1.4 Governance Mapping
 #### 1.5 Launch Streamlit App (Colab)
