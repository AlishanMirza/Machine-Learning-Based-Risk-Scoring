# AI-assisted Governance, Risk & Compliance (GRC) engine integrating CVE intelligence, ML-based severity prediction, policy alignment, and human-in-the-loop governance.

## Overview
This system converts raw CVE data into structured, explainable, and governance-ready intelligence. It integrates AI risk estimation (SBERT + LightGBM), NIST/enterprise policy alignment, asset criticality, and a Streamlit-based human-review portal. The output is a complete Security Governance Report suitable for SOC workflows, audit trails, and compliance documentation.

The full pipeline is implemented in:
GRC_Implementation_final.ipynb


## Research Objectives

	1) Transform raw vulnerability intelligence into structured, explainable risk insights.
	2) Integrate machine learning predictions with governance policies to produce actionable GRC decisions.
	3) Ensure human-in-the-loop validation for high-risk or ambiguous cases.
	4) Maintain auditable and traceable outputs for enterprise compliance.
## Methodology

The methodology follows a structured, sequential pipeline designed for robustness and reproducibility:
1. **Data Collection**  
   - Fetched CVE data (1999–2025) from NVD and Espressif datasets.  
   - Each entry includes vulnerability description, CWE code, and CVSS base score.
2. **Feature Engineering**  
   - **Textual features:** Sentence embeddings using SBERT (`all-MiniLM-L6-v2`).  
   - **Categorical features:** CWE category encoded numerically.  
   - **Keyword & structural features:**  
     - Description length  
     - Indicators for terms like `overflow`, `injection`, `remote`, `execution`, etc.
3. **Model Training**  
   - Built an **ensemble stacking classifier**:  
     - LightGBM  
     - XGBoost  
     - Logistic Regression (meta-learner)  
   - Optimized via stratified K-Fold cross-validation.
4. **Evaluation Metrics**  
   - Accuracy, Precision, Recall, F1-Score, ROC-AUC.  
   - Confusion matrix and feature importance visualizations.
5. **Deployment**  
   - Exported trained pipeline (`pipeline.pkl`).  
   - Built a **Streamlit app (`risk-scoring.py`)** for real-time inference.

## Expected Contributions

This research provides several key contributions to the field of automated cybersecurity and risk management:
- A hybrid ML + NLP system that learns contextual severity meaning from vulnerability text.  
- Faster and more consistent vulnerability scoring compared to manual analysis.  
- Demonstration of integrating cybersecurity data with modern transformer embeddings.  

## DATASET

The dataset was constructed from real-world vulnerability data sourced from the National Vulnerability Database (NVD). Access was facilitated through the public GitHub mirror maintained by Espressif: [espressif/esp-nvd-mirror](https://github.com/espressif/esp-nvd-mirror).

The data includes CVEs published between 2020 and 2025. Key fields extracted for this project include the English-language `Description`, `CWE` (Common Weakness Enumeration), `CVSS_Score`, and the official `Severity` rating, which serves as our target label. The final dataset used for training was thoroughly cleaned and deduplicated to ensure data quality and model validity.

## Run Application
pip install -r requirements.txt -
1.Run 1-5.ipynb files - 2.Run final.ipynb
- 3. streamlit run risk-scoring.py

**Example Sample:**
```csv
description,cwe
"Sensitive cookies transmitted over HTTP instead of HTTPS",CWE-614
"Buffer overflow in file upload parser allows remote code execution",CWE-120
