#!/usr/bin/env python3
import argparse, json, logging, os, random, sys
from datetime import datetime
from pathlib import Path
from typing import List
import joblib, numpy as np, pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from imblearn.combine import SMOTEENN
from imblearn.pipeline import Pipeline as ImbPipeline
import torch
from sentence_transformers import SentenceTransformer
import shap

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_SSBERT = "all-MiniLM-L6-v2"
SUPPORTED_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

def find_json_files(root_dir: Path) -> List[Path]:
    files = list(root_dir.rglob("*.json"))
    logger.info("Found %d JSON files in %s", len(files), root_dir)
    return files

def parse_cve_file(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("Failed to parse %s: %s", path, e)
        return {}

def get_cve_id(obj: dict) -> str:
    return obj.get("cve", {}).get("CVE_data_meta", {}).get("ID") or obj.get("id") or obj.get("cve_id") or "<unknown>"

def get_published_date(obj: dict) -> str:
    return obj.get("publishedDate") or obj.get("published") or obj.get("lastModified") or ""

def get_description(obj: dict) -> str:
    try:
        dd = obj.get("cve", {}).get("description", {}).get("description_data", [])
        if dd and isinstance(dd, list):
            texts = [d.get("value", "") for d in dd if isinstance(d, dict)]
            return max(texts, key=len) if texts else ""
        return obj.get("summary") or obj.get("description") or ""
    except Exception:
        return obj.get("description") or ""

def get_cwe(obj: dict) -> str:
    try:
        ptd = obj.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
        values = []
        for entry in ptd:
            for desc in entry.get("description", []):
                v = desc.get("value")
                if v: values.append(v)
        return ";".join(values) if values else ""
    except Exception:
        return ""

def get_cpe_list(obj: dict) -> List[str]:
    cpes = []
    try:
        nodes = obj.get("configurations", {}).get("nodes", [])
        for n in nodes:
            for match in n.get("cpe_match", []) + n.get("children", []):
                if isinstance(match, dict):
                    uri = match.get("cpe23Uri") or match.get("cpe_uri")
                    if uri: cpes.append(uri)
                elif isinstance(match, list):
                    for m2 in match:
                        if isinstance(m2, dict):
                            uri = m2.get("cpe23Uri")
                            if uri: cpes.append(uri)
        uniq = list(dict.fromkeys([c for c in cpes if c]))
        return uniq
    except Exception:
        return []

def map_cvss_to_severity(obj: dict) -> str:
    try:
        impacts = obj.get("impact", {})
        cvss_v3 = impacts.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")
        if cvss_v3 is None:
            cvss_v3 = impacts.get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore")
        if cvss_v3 is None: return ""
        score = float(cvss_v3)
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        return "LOW"
    except Exception:
        return ""

def parse_all_cves(vulzoo_dir: Path) -> pd.DataFrame:
    records = []
    files = find_json_files(vulzoo_dir)
    for f in files:
        obj = parse_cve_file(f)
        if not obj: continue
        records.append({
            "cve_id": get_cve_id(obj),
            "description": get_description(obj),
            "cwe": get_cwe(obj),
            "cpes": get_cpe_list(obj),
            "published": get_published_date(obj),
            "cvss_severity": map_cvss_to_severity(obj),
            "source_file": str(f),
        })
    df = pd.DataFrame(records)
    logger.info("Parsed DataFrame with %d records", len(df))
    try:
        df["published_dt"] = pd.to_datetime(df["published"], errors="coerce")
    except Exception:
        df["published_dt"] = pd.NaT
    return df

class SentenceTransformerWrapper:
    def __init__(self, model_name: str = DEFAULT_SSBERT, device: str = "cpu", batch_size: int = 64):
        self.model_name = model_name
        self.device = device
        self.batch_size = batch_size
        self._model = None

    def _init_model(self):
        if self._model is None:
            logger.info("Loading SBERT model %s on device %s", self.model_name, self.device)
            self._model = SentenceTransformer(self.model_name, device=self.device)

    def encode(self, texts: List[str]) -> np.ndarray:
        if texts is None or len(texts) == 0: return np.zeros((0, self.get_embedding_dim()), dtype=np.float32)
        self._init_model()
        embs = self._model.encode(texts, batch_size=self.batch_size, show_progress_bar=True, convert_to_numpy=True)
        return np.asarray(embs, dtype=np.float32)

    def get_embedding_dim(self) -> int:
        self._init_model()
        return self._model.get_sentence_embedding_dimension()

    def save(self, output_path: Path):
        meta = {"model_name": self.model_name, "device": self.device, "batch_size": self.batch_size}
        joblib.dump(meta, output_path)
        logger.info("Saved SBERT wrapper meta to %s", output_path)

    @staticmethod
    def load(meta_path: Path):
        meta = joblib.load(meta_path)
        return SentenceTransformerWrapper(meta.get("model_name", DEFAULT_SSBERT), device=meta.get("device", "cpu"), batch_size=meta.get("batch_size", 64))

def build_feature_pipelines(sbert_wrapper: SentenceTransformerWrapper, tfidf_desc_mx=2000, tfidf_cwe_mx=200, tfidf_cpe_mx=1000):
    desc_vec = TfidfVectorizer(max_features=tfidf_desc_mx, ngram_range=(1, 2), stop_words="english")
    cwe_vec = TfidfVectorizer(max_features=tfidf_cwe_mx, token_pattern=r"(?u)\b\w+\b")
    cpe_vec = TfidfVectorizer(max_features=tfidf_cpe_mx, token_pattern=r"(?u)\b[^:]+\b")
    tfidf_pipeline = {"desc_vec": desc_vec, "cwe_vec": cwe_vec, "cpe_vec": cpe_vec, "sbert_wrapper": sbert_wrapper}

    def fit_transformers(df: pd.DataFrame):
        descs = df["description"].fillna("").astype(str).tolist()
        cwes = df["cwe"].fillna("").astype(str).tolist()
        cpes = [" ".join(row) if isinstance(row, list) else str(row) for row in df["cpes"].fillna("").tolist()]
        X_desc = desc_vec.fit_transform(descs)
        X_cwe = cwe_vec.fit_transform(cwes)
        X_cpe = cpe_vec.fit_transform(cpes)
        return X_desc, X_cwe, X_cpe

    def transform(df: pd.DataFrame):
        descs = df["description"].fillna("").astype(str).tolist()
        cwes = df["cwe"].fillna("").astype(str).tolist()
        cpes = [" ".join(row) if isinstance(row, list) else str(row) for row in df["cpes"].fillna("").tolist()]
        X_desc = desc_vec.transform(descs)
        X_cwe = cwe_vec.transform(cwes)
        X_cpe = cpe_vec.transform(cpes)
        X_sbert = sbert_wrapper.encode(descs)
        return X_desc, X_cwe, X_cpe, X_sbert

    tfidf_pipeline["fit_transformers"] = fit_transformers
    tfidf_pipeline["transform"] = transform
    return tfidf_pipeline

def prepare_feature_matrix(X_desc, X_cwe, X_cpe, X_sbert):
    X_sbert_sparse = csr_matrix(X_sbert)
    X_combined = hstack([X_desc, X_cwe, X_cpe, X_sbert_sparse], format="csr")
    return X_combined

# train + save
def train_and_save_pipeline(vulzoo_cve_dir: str, output_dir: str, sbert_model_name: str = DEFAULT_SSBERT, gpu_device_id: int = 0, sbert_batch_size: int = 64, max_train_rows: int = 0):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    df = parse_all_cves(Path(vulzoo_cve_dir))
    if df.empty: logger.error("No CVE data parsed. Exiting."); sys.exit(1)
    df["label"] = df["cvss_severity"].fillna("").replace("", np.nan)
    labeled = df[df["label"].notna()].copy()
    if labeled.empty:
        def heur(desc): d = str(desc).lower(); 
        if any(k in d for k in ["rce","remote code","buffer overflow","heap overflow"]): return "CRITICAL"
        if any(k in d for k in ["privilege","elevation","auth bypass","bypass"]): return "HIGH"
        if len(d)>400: return "MEDIUM"
        return "LOW"
        df["label"] = df["description"].apply(heur)
        labeled = df.copy()
    labeled = labeled.sort_values("published_dt", na_position="first")
    if max_train_rows>0: labeled=labeled.head(max_train_rows)
    pct_holdout=0.15; cutoff_idx=int(len(labeled)*(1.0-pct_holdout))
    train_df=labeled.iloc[:max(1,cutoff_idx)].reset_index(drop=True)
    calib_df=labeled.iloc[cutoff_idx:].reset_index(drop=True)
    device="cpu"; 
    if torch.cuda.is_available(): device=f"cuda:{gpu_device_id}"
    sbert_wrapper=SentenceTransformerWrapper(model_name=sbert_model_name,device=device,batch_size=sbert_batch_size)
    tfidf_pipeline=build_feature_pipelines(sbert_wrapper)
    X_desc_train,X_cwe_train,X_cpe_train=tfidf_pipeline["fit_transformers"](train_df)
    X_sbert_train=sbert_wrapper.encode(train_df["description"].fillna("").astype(str).tolist())
    X_train=prepare_feature_matrix(X_desc_train,X_cwe_train,X_cpe_train,X_sbert_train)
    y_train=train_df["label"].astype(str).values
    sampler=SMOTEENN(random_state=42)
    base_clf=RandomForestClassifier(n_estimators=200,n_jobs=-1,class_weight="balanced",random_state=42)
    imb_pipeline=ImbPipeline([("sampler",sampler),("clf",base_clf)])
    try: X_train_dense=X_train.toarray()
    except MemoryError: n_samples=min(30000,X_train.shape[0]); idx=np.random.choice(X_train.shape[0],n_samples,replace=False); X_train_dense=X_train[idx].toarray(); y_train=y_train[idx]
    imb_pipeline.fit(X_train_dense,y_train)
    X_desc_calib,X_cwe_calib,X_cpe_calib,X_sbert_calib=tfidf_pipeline["transform"](calib_df)
    X_calib=prepare_feature_matrix(X_desc_calib,X_cwe_calib,X_cpe_calib,X_sbert_calib)
    try: X_calib_dense=X_calib.toarray()
    except MemoryError: n_calib=min(1000,X_calib.shape[0]); idx=np.random.choice(X_calib.shape[0],n_calib,replace=False); X_calib_dense=X_calib[idx].toarray(); y_calib=calib_df["label"].astype(str).values[idx]
    else: y_calib=calib_df["label"].astype(str).values
    try: calibrated=CalibratedClassifierCV(imb_pipeline,cv="prefit",method="isotonic"); calibrated.fit(X_calib_dense,y_calib)
    except Exception as e: calibrated=CalibratedClassifierCV(imb_pipeline,cv="prefit",method="sigmoid"); calibrated.fit(X_calib_dense,y_calib)
    bg_sample_size=min(200,X_train_dense.shape[0]); bg_idx=np.random.choice(X_train_dense.shape[0],bg_sample_size,replace=False); X_bg=X_train_dense[bg_idx]
    def predict_proba_for_shap(X_input: np.ndarray)->np.ndarray: return calibrated.predict_proba(X_input)
    try: explainer=None; explainer=shap.KernelExplainer(predict_proba_for_shap,X_bg)
    except Exception: explainer=None
    joblib.dump(tfidf_pipeline,out/"tfidf_pipeline.pkl")
    sbert_wrapper.save(out/"sbert_wrapper_meta.pkl")
    joblib.dump(calibrated,out/"calibrated_classifier.pkl")
    metadata={"model_version":"ml_pipeline_v1.0","trained_on":datetime.utcnow().isoformat()+"Z","sbert_model":sbert_model_name,"sbert_device":device,"sbert_batch_size":sbert_batch_size,"classes":list(calibrated.classes_)}
    with open(out/"metadata.json","w",encoding="utf-8") as f: json.dump(metadata,f,indent=2)
    try:
        if explainer is not None: joblib.dump(explainer,out/"grc_explainer.pkl")
        np.savez_compressed(out/"explainer_bg.npz",X_bg=X_bg)
    except Exception: np.savez_compressed(out/"explainer_bg.npz",X_bg=X_bg)
    return out

def main():
    parser=argparse.ArgumentParser(description="Train ML pipeline for Vulnerability Intelligence.")
    parser.add_argument("--vulzoo_cve_dir",required=True)
    parser.add_argument("--output_dir",default="artifacts")
    parser.add_argument("--sbert_model",default=DEFAULT_SSBERT)
    parser.add_argument("--gpu_device_id",type=int,default=0)
    parser.add_argument("--sbert_batch_size",type=int,default=64)
    parser.add_argument("--max_train_rows",type=int,default=0)
    args=parser.parse_args()
    train_and_save_pipeline(args.vulzoo_cve_dir,args.output_dir,args.sbert_model,args.gpu_device_id,args.sbert_batch_size,args.max_train_rows)

if __name__=="__main__": main()