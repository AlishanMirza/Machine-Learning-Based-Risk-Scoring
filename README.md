# Automated CVE Risk Scoring using Machine Learning

## Research Objectives

The primary objective of this research is to develop and validate a machine learning pipeline capable of automatically classifying the severity of Common Vulnerabilities and Exposures (CVEs). We aim to:
1.  Develop a model that can accurately predict a CVE's risk level (Critical, High, Medium, Low) based on its textual description and metadata.
2.  Investigate the effectiveness of modern Natural Language Processing (NLP) techniques, specifically Sentence-BERT, for capturing the semantic meaning of vulnerability text.
3.  Evaluate whether a stacked ensemble of advanced classifiers (XGBoost, LightGBM) provides superior performance compared to single-model approaches.

## Methodology

The methodology follows a structured, sequential pipeline designed for robustness and reproducibility:
1.  **Data Acquisition:** CVE data from 2020-2025 was programmatically fetched from a public mirror of the National Vulnerability Database (NVD).
2.  **Data Preparation:** The raw JSON data was parsed to extract key fields. The dataset was then cleaned by removing entries with missing essential information and deduplicated based on the vulnerability description to prevent data leakage.
3.  **Feature Engineering:** The core of our novel approach. We used a pre-trained **Sentence-BERT** model to convert CVE descriptions into rich, semantic vector embeddings. Categorical features like CWE were One-Hot Encoded.
4.  **Model Training:** A **Stacked Classifier** was implemented using a scikit-learn `Pipeline`. LightGBM and XGBoost served as the base learners, and a Logistic Regression model served as the final meta-classifier. The entire training process was designed to prevent data leakage by splitting the data *before* any preprocessing was fit.
5.  **Model Interpretation:** The final, trained model was analyzed using **SHAP (SHapley Additive exPlanations)** to understand which features were most influential in its predictions.

## Expected Contributions

This research provides several key contributions to the field of automated cybersecurity and risk management:
1.  A complete, end-to-end pipeline demonstrating a robust method for CVE risk scoring, including rigorous steps to identify and mitigate multiple forms of data leakage.
2.  Strong evidence that semantic feature engineering using **Sentence-BERT** is a highly effective technique for this problem, capable of extracting meaningful patterns from unstructured text where traditional keyword-based methods would fail.
3.  A high-performing **Stacked Ensemble model** that serves as a new, powerful baseline for future research in automated vulnerability prioritization.

## DATASET

The dataset was constructed from real-world vulnerability data sourced from the National Vulnerability Database (NVD). Access was facilitated through the public GitHub mirror maintained by Espressif: [espressif/esp-nvd-mirror](https://github.com/espressif/esp-nvd-mirror).

The data includes CVEs published between 2020 and 2025. Key fields extracted for this project include the English-language `Description`, `CWE` (Common Weakness Enumeration), `CVSS_Score`, and the official `Severity` rating, which serves as our target label. The final dataset used for training was thoroughly cleaned and deduplicated to ensure data quality and model validity.
