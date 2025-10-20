# Automated CVE Risk Scoring using Machine Learning

## Research Objectives

The primary objective of this research is to develop and validate a machine learning pipeline capable of automatically classifying the severity of Common Vulnerabilities and Exposures (CVEs). We aim to:
1.  Develop a model that can accurately predict a CVE's risk level (Critical, High, Medium, Low) based on its textual description and metadata.
2.  Investigate the effectiveness of modern Natural Language Processing (NLP) techniques, specifically Sentence-BERT, for capturing the semantic meaning of vulnerability text.
3.  Evaluate whether a stacked ensemble of advanced classifiers (XGBoost, LightGBM) provides superior performance compared to single-model approaches.

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
Run 1-5.ipynb files -
- streamlit run risk-scoring.py

**Example Sample:**
```csv
description,cwe
"Sensitive cookies transmitted over HTTP instead of HTTPS",CWE-614
"Buffer overflow in file upload parser allows remote code execution",CWE-120
