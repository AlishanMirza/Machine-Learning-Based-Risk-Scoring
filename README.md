# AI-assisted Governance, Risk & Compliance (GRC) engine integrating CVE intelligence, ML-based severity prediction, policy alignment, and human-in-the-loop governance.

## Overview
This system converts raw CVE data into structured, explainable, and governance-ready intelligence. It integrates AI risk estimation (SBERT + LightGBM), NIST/enterprise policy alignment, asset criticality, and a Streamlit-based human-review portal. The output is a complete Security Governance Report suitable for SOC workflows, audit trails, and compliance documentation.

The full pipeline is implemented in:
GRC_Implementation_final.ipynb


## Research Objectives
•	Transform raw vulnerability intelligence into structured, explainable risk insights.
•	Integrate machine learning predictions with governance policies to produce actionable GRC decisions.
•	Ensure human-in-the-loop validation for high-risk or ambiguous cases.
•	Maintain auditable and traceable outputs for enterprise compliance.

## Research Gap
•	Most existing tools output only severity labels or CVSS scores without aligning to governance policy or control posture.
•	Few prototypes create explainable, governance-ready artifacts.
•	End-to-end integration (CVE ingestion → ML → GRC mapping → human review → governance report) is largely missing from industry and academic literature.

## Key Goals
•	Generate calibrated AI_Risk_Intel objects enriched with text embeddings, CVE metadata, model probabilities, and explainability fields.
•	Convert predictions into Governance_Action_Packets using crosswalks between ML risk, NIST SP 800-53 controls, enterprise policies, and asset criticality.
•	Route high-risk cases to human analysts and record the final decisions.
•	Produce a complete Security_Governance_Report for audit and compliance validation.
	
## Methodology

**Data Ingestion**
	•	Download CVE records from the NVD mirror Espressif: [espressif/esp-nvd-mirror](https://github.com/espressif/esp-nvd-mirror).
	•	Normalize structure into: description, CWE, CPE, vendors/products, CVSS vectors, publish timestamps.

**Feature Engineering**
	•	SBERT text embeddings (SentenceTransformers + PyTorch).
	•	CVSS score vectors (8 dimensions).
	•	CWE indicators, tokenized vendor/product keywords.
	•	Description length, asset criticality (from enterprise catalog).
	•	Model-ready numerical feature matrix.

**Machine Learning**
	•	Random Forest, XGBoost, and LightGBM considered; LightGBM chosen as the primary production model.
	•	Class imbalance handled using SMOTE and class-weighting.
	•	Probability calibration (CalibratedClassifierCV) for trustworthy governance thresholds.
	•	Evaluation: Accuracy, F1, confusion matrix, per-class precision/recall.

**Governance Mapping**
	•	Map AI predictions to NIST SP 800-53 rev5 controls (via enterprise control catalog).
	•	Derive governance posture (Compliant / At-Risk / Non-Compliant).
	•	Generate Governance_Action_Packet objects containing:
	•	Required controls
	•	Affected assets
	•	Recommended governance actions
	•	Risk explanations
	•	Whether human review is required

**Human-in-the-Loop**
	•	Streamlit interface presents each Governance_Action_Packet.
	•	Analysts can Approve / Override / Reject.
	•	Decisions merged into the final Security_Governance_Report.

**Web UI**
	•	Built with Streamlit (component3_review_app.py).
	•	Filters, object inspection, governance workflow, and CSV/JSONL export.
	•	In Colab, Cloudflare tunnel enables external sharing.

## Expected Contributions
•	Complete, reproducible prototype for AI-assisted security governance.
•	Explainable ML severity predictions, calibrated for GRC workflows.
•	Formal governance objects (AI_Risk_Intel & Governance_Action_Packet).
•	Human-in-the-loop GRC decisioning platform.
•	Auditable Security_Governance_Report suitable for enterprise use.  

## DATASET

The dataset was constructed from real-world vulnerability data sourced from the National Vulnerability Database (NVD). Access was facilitated through the public GitHub mirror maintained by Espressif: [espressif/esp-nvd-mirror](https://github.com/espressif/esp-nvd-mirror).

The data includes CVEs published between 2020 and 2025. Key fields extracted for this project include the English-language `Description`, `CWE` (Common Weakness Enumeration), `CVSS_Score`, and the official `Severity` rating, which serves as our target label. The final dataset used for training was thoroughly cleaned and deduplicated to ensure data quality and model validity.

## Run Application
### 1. Install Dependencies
### 2. Run in Google Colab
#### 2.1 Setup Project Folders
#### 2.2 Download CVE Dataset
#### 2.3 Generate AI_Risk_Intel
#### 2.4 Governance Mapping
#### 2.5 Launch Streamlit App

**Example Sample:**
```csv
description,cwe
"Sensitive cookies transmitted over HTTP instead of HTTPS",CWE-614
"Buffer overflow in file upload parser allows remote code execution",CWE-120
