#!/usr/bin/env python3
import argparse, json, logging, sys
from datetime import datetime
from pathlib import Path
from typing import List
import joblib, numpy as np, pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
import lightgbm as lgb
import xgboost as xgb
from imblearn.combine import SMOTEENN
from imblearn.pipeline import Pipeline as ImbPipeline
import torch
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_SSBERT = "all-MiniLM-L6-v2"
SUPPORTED_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# ----------------------- Parsing & Utilities ----------------------- #

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

# CVE info extraction helpers
def get_cve_id(obj: dict) -> str:
    return obj.get("cve", {}).get("CVE_data_meta", {}).get("ID") or obj.get("id") or obj.get("cve_id") or "<unknown>"

def get_description(obj: dict) -> str:
    try:
        dd = obj.get("cve", {}).get("description", {}).get("description_data", [])
        texts = [d.get("value", "") for d in dd if isinstance(d, dict)]
        return max(texts, key=len) if texts else obj.get("summary") or obj.get("description") or ""
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
        return list(dict.fromkeys([c for c in cpes if c]))
    except Exception:
        return []

def get_published_date(obj: dict) -> str:
    return obj.get("publishedDate") or obj.get("published") or obj.get("lastModified") or ""

def map_cvss_to_severity(obj: dict) -> str:
    try:
        impacts = obj.get("impact", {})
        cvss = impacts.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore") or \
               impacts.get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore")
        if cvss is None: return ""
        score = float(cvss)
        if score >= 9: return "CRITICAL"
        if score >= 7: return "HIGH"
        if score >= 4: return "MEDIUM"
        return "LOW"
    except Exception:
        return ""

def parse_all_cves(vulzoo_dir: Path) -> pd.DataFrame:
    records = []
    for f in find_json_files(vulzoo_dir):
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
    df["published_dt"] = pd.to_datetime(df["published"], errors="coerce")
    logger.info("Parsed DataFrame with %d records", len(df))
    return df

# ----------------------- SBERT Wrapper ----------------------- #

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
        if not texts: return np.zeros((0, self.get_embedding_dim()), dtype=np.float32)
        self._init_model()
        return np.asarray(self._model.encode(texts, batch_size=self.batch_size, show_progress_bar=True, convert_to_numpy=True), dtype=np.float32)

    def get_embedding_dim(self) -> int:
        self._init_model()
        return self._model.get_sentence_embedding_dimension()

    def save(self, output_path: Path):
        joblib.dump({"model_name": self.model_name, "device": self.device, "batch_size": self.batch_size}, output_path)
        logger.info("Saved SBERT wrapper metadata to %s", output_path)

    @staticmethod
    def load(meta_path: Path):
        meta = joblib.load(meta_path)
        return SentenceTransformerWrapper(meta.get("model_name", DEFAULT_SSBERT),
                                         device=meta.get("device", "cpu"),
                                         batch_size=meta.get("batch_size", 64))

# ----------------------- Feature Pipelines ----------------------- #

from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix

def build_feature_pipelines(sbert_wrapper: SentenceTransformerWrapper, tfidf_desc_mx=2000, tfidf_cwe_mx=200, tfidf_cpe_mx=1000):
    desc_vec = TfidfVectorizer(max_features=tfidf_desc_mx, ngram_range=(1,2), stop_words="english")
    cwe_vec = TfidfVectorizer(max_features=tfidf_cwe_mx, token_pattern=r"(?u)\b\w+\b")
    cpe_vec = TfidfVectorizer(max_features=tfidf_cpe_mx, token_pattern=r"(?u)\b[^:]+\b")
    pipeline = {"desc_vec": desc_vec, "cwe_vec": cwe_vec, "cpe_vec": cpe_vec, "sbert_wrapper": sbert_wrapper}

    def fit_transformers(df: pd.DataFrame):
        descs = df["description"].fillna("").astype(str).tolist()
        cwes = df["cwe"].fillna("").astype(str).tolist()
        cpes = [" ".join(x) if isinstance(x,list) else str(x) for x in df["cpes"].fillna("").tolist()]
        X_desc, X_cwe, X_cpe = desc_vec.fit_transform(descs), cwe_vec.fit_transform(cwes), cpe_vec.fit_transform(cpes)
        return X_desc, X_cwe, X_cpe

    def transform(df: pd.DataFrame):
        descs = df["description"].fillna("").astype(str).tolist()
        cwes = df["cwe"].fillna("").astype(str).tolist()
        cpes = [" ".join(x) if isinstance(x,list) else str(x) for x in df["cpes"].fillna("").tolist()]
        X_desc, X_cwe, X_cpe = desc_vec.transform(descs), cwe_vec.transform(cwes), cpe_vec.transform(cpes)
        X_sbert = sbert_wrapper.encode(descs)
        return X_desc, X_cwe, X_cpe, X_sbert

    pipeline["fit_transformers"] = fit_transformers
    pipeline["transform"] = transform
    return pipeline

def prepare_feature_matrix(X_desc, X_cwe, X_cpe, X_sbert):
    X_sbert_sparse = csr_matrix(X_sbert)
    return hstack([X_desc, X_cwe, X_cpe, X_sbert_sparse], format="csr")

# ----------------------- Model Training ----------------------- #

def train_model(X, y, model_type="rf"):
    """Train RF, LightGBM, or XGBoost."""
    sampler = SMOTEENN(random_state=42)
    if model_type=="rf":
        clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, class_weight="balanced", random_state=42)
    elif model_type=="lgb":
        clf = lgb.LGBMClassifier(n_estimators=500, n_jobs=-1, class_weight="balanced", random_state=42)
    elif model_type=="xgb":
        clf = xgb.XGBClassifier(n_estimators=500, n_jobs=-1, scale_pos_weight=1, use_label_encoder=False, eval_metric="mlogloss", random_state=42)
    else:
        raise ValueError("model_type must be 'rf', 'lgb', or 'xgb'")

    pipeline = ImbPipeline([("sampler", sampler), ("clf", clf)])
    try:
        X_dense = X.toarray()
    except MemoryError:
        n_samples = min(30000, X.shape[0])
        idx = np.random.choice(X.shape[0], n_samples, replace=False)
        X_dense, y = X[idx].toarray(), y[idx]
    pipeline.fit(X_dense, y)
    return pipeline

# ----------------------- Full Training Pipeline ----------------------- #

def train_and_save_pipeline(vulzoo_dir: str, output_dir: str, model_type="rf", sbert_model_name: str=DEFAULT_SSBERT, gpu_device_id:int=0, batch_size:int=64, max_train_rows:int=0):
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    df = parse_all_cves(Path(vulzoo_dir))
    if df.empty: logger.error("No CVE data parsed. Exiting."); sys.exit(1)
    
    df["label"] = df["cvss_severity"].fillna("").replace("", pd.NA)
    labeled = df[df["label"].notna()].copy()
    if labeled.empty:
        labeled["label"] = df["description"].apply(lambda d: "LOW")  # fallback
        labeled = df.copy()

    if max_train_rows>0: labeled = labeled.head(max_train_rows)
    train_df, calib_df = train_test_split(labeled, test_size=0.15, shuffle=False)

    device = f"cuda:{gpu_device_id}" if torch.cuda.is_available() else "cpu"
    sbert_wrapper = SentenceTransformerWrapper(sbert_model_name, device=device, batch_size=batch_size)
    tfidf_pipeline = build_feature_pipelines(sbert_wrapper)

    X_desc_train, X_cwe_train, X_cpe_train = tfidf_pipeline["fit_transformers"](train_df)
    X_sbert_train = sbert_wrapper.encode(train_df["description"].fillna("").astype(str).tolist())
    X_train = prepare_feature_matrix(X_desc_train, X_cwe_train, X_cpe_train, X_sbert_train)
    y_train = train_df["label"].astype(str).values

    clf_pipeline = train_model(X_train, y_train, model_type=model_type)

    # Save artifacts
    joblib.dump(tfidf_pipeline, out/"tfidf_pipeline.pkl")
    sbert_wrapper.save(out/"sbert_wrapper_meta.pkl")
    joblib.dump(clf_pipeline, out/"classifier.pkl")
    metadata = {"model_version":"ml_pipeline_v2", "trained_on":datetime.utcnow().isoformat()+"Z", "model_type":model_type, "classes":list(clf_pipeline.named_steps["clf"].classes_)}
    with open(out/"metadata.json","w") as f: json.dump(metadata,f,indent=2)
    logger.info("Training complete. Artifacts saved to %s", out)
    return out

# ----------------------- CLI ----------------------- #

def main():
    parser = argparse.ArgumentParser(description="Train CVE ML Pipeline with RF/LGB/XGB.")
    parser.add_argument("--vulzoo_dir", required=True)
    parser.add_argument("--output_dir", default="artifacts")
    parser.add_argument("--model_type", choices=["rf","lgb","xgb"], default="rf")
    parser.add_argument("--sbert_model", default=DEFAULT_SSBERT)
    parser.add_argument("--gpu_device_id", type=int, default=0)
    parser.add_argument("--batch_size", type=int, default=64)
    parser.add_argument("--max_train_rows", type=int, default=0)
    args = parser.parse_args()

    train_and_save_pipeline(args.vulzoo_dir, args.output_dir, args.model_type, args.sbert_model, args.gpu_device_id, args.batch_size, args.max_train_rows)

if __name__=="__main__":
    main()