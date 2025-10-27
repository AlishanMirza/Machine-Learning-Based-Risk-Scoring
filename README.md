# AI Governance Assistant

## Research Objectives
- Transform raw vulnerability intelligence into structured, explainable risk insights.  
- Integrate AI predictions with governance policies for actionable decision-making.  
- Ensure human-in-the-loop review for high-risk or ambiguous cases.  
- Provide auditable and traceable security governance reports.

## Research Gap
- Existing systems mainly produce risk scores or severity labels without policy alignment.  
- Lack of explainable, governance-ready outputs that include human oversight.  
- Few prototypes demonstrate end-to-end integration of AI, GRC mapping, and human validation.

## Key Goals
- Generate calibrated AI_Risk_Intel objects from CVE data.  
- Map AI predictions to GRC actions with clear explanations.  
- Enable human review and approval of high-risk decisions.  
- Maintain a complete audit trail for compliance and SOC workflows.

## Methodology
- **Data Ingestion:** Collect and normalize CVE data (VulZoo 2024 & 2025).  
- **Feature Engineering:** Extract CWE, description tokens, description length, asset criticality, CVSS, and CPE.  
- **ML Modeling:** Train RF, XGBoost and also LightGBM, with SMOTE balancing; generate probability-calibrated severity predictions.  
- **Governance Mapping:** Convert AI predictions into Governance_Action_Packet using GRC ruleset.  
- **Human-in-the-Loop:** Route high-risk cases to analysts; log final decisions in Security_Governance_Report.  
- **Web UI:** Streamlit interface for visualization and manual validation.

## Expected Contributions
- End-to-end prototype transforming vulnerability intelligence into actionable governance decisions.  
- Explainable and auditable AI risk predictions integrated with GRC policies.  
- Demonstrated methodology for human-in-the-loop risk validation.  
- Structured output objects (AI_Risk_Intel, Governance_Action_Packet, Security_Governance_Report) ready for enterprise use.

## Dataset
- **VulZoo CVE dataset** covering 2024 and 2025.  
- Contains CVE description, CWE, CPE, asset criticality, CVSS, and vendor metadata.  
- Provides sufficient coverage for training, testing, and governance mapping.

## Running the App
1. Clone the repository.  
2. Install dependencies: `pip install -r requirements.txt`  
3. Launch the Streamlit app: `streamlit run app.py`  
4. Upload or point to VulZoo CVE dataset.  
5. Train or load the LightGBM model.  
6. Review AI_Risk_Intel outputs and approve high-risk cases via the interface.  
7. Export final Security_Governance_Report for audit and compliance.
