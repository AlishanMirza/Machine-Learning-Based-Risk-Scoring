import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ---------------------------
# Dataclasses
# ---------------------------
@dataclass
class AI_Risk_Intel:
    cve_id: str
    predicted_severity: str
    confidence: float
    prediction_proba: Dict[str, float]
    key_features: Dict[str, float]
    model_version: str
    timestamp: str


@dataclass
class Governance_Action_Packet:
    cve_id: str
    intel: AI_Risk_Intel
    asset_criticality: str
    recommended_action: str
    policy_reference: str
    requires_human: bool
    explanation: str
    timestamp: str


# ---------------------------
# Helper: criticality order
# ---------------------------
CRIT_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _highest_criticality(values: List[str]) -> str:
    best = "LOW"
    for v in values:
        if v and v.upper() in CRIT_ORDER and CRIT_ORDER[v.upper()] > CRIT_ORDER[best]:
            best = v.upper()
    return best


# ---------------------------
# GRCEngine
# ---------------------------
class GRCEngine:
    def __init__(self, policy_ruleset_path: str = "mock_data/policy_ruleset.json", asset_db_path: str = "mock_data/asset_database.json"):
        self.policy_ruleset_path = Path(policy_ruleset_path)
        self.asset_db_path = Path(asset_db_path)
        self.rules = self._load_json(self.policy_ruleset_path)
        self.asset_db = self._load_json(self.asset_db_path)
        logger.info("Loaded policy rules from %s (%d rules)", self.policy_ruleset_path, len(self.rules))
        logger.info("Loaded asset DB from %s (%d entries)", self.asset_db_path, len(self.asset_db))

    @staticmethod
    def _load_json(p: Path) -> dict:
        if not p.exists():
            logger.warning("JSON path %s does not exist; returning empty dict", p)
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Failed to parse %s: %s", p, e)
            return {}

    def get_asset_criticality(self, cpe_list: List[str]) -> str:
        """
        Perform substring matching between provided CPEs and keys in asset_db.
        If multiple matches, return the highest criticality.
        """
        matches = []
        for cpe in cpe_list or []:
            cp = cpe.lower()
            for asset_key, crit in self.asset_db.items():
                if asset_key.lower() in cp or asset_key.lower().replace(":", "_") in cp:
                    matches.append(crit.upper())
        if not matches:
            return "LOW"
        return _highest_criticality(matches)

    def _format_top_features(self, key_features: Dict[str, float], top_n: int = 3) -> str:
        if not key_features:
            return "No feature explanation available."
        # sort by absolute impact
        sorted_feats = sorted(key_features.items(), key=lambda kv: abs(kv[1]), reverse=True)[:top_n]
        return ", ".join([f"{k} ({v:+.3f})" for k, v in sorted_feats])

    def generate_governance_packet(self, intel: AI_Risk_Intel, cpe_list: List[str]) -> Governance_Action_Packet:
        asset_crit = self.get_asset_criticality(cpe_list)
        key = f"{intel.predicted_severity}_{asset_crit}"
        rule = self.rules.get(key) or self.rules.get("DEFAULT") or {"action": "Log for review.", "policy": "N/A", "hitl_required": False}

        # Confidence threshold: force human if below threshold
        confidence_threshold = 0.65
        hitl_by_conf = intel.confidence < confidence_threshold
        requires_human = bool(rule.get("hitl_required", False)) or hitl_by_conf

        explanation_lines = [
            f"Predicted severity: {intel.predicted_severity} (confidence {intel.confidence:.2%})",
            f"Asset criticality (inferred): {asset_crit}",
            f"Top features: {self._format_top_features(intel.key_features, top_n=5)}",
            f"Mapped policy: {rule.get('policy', 'N/A')}",
        ]
        if hitl_by_conf:
            explanation_lines.append(f"Human review recommended due to low confidence (<{confidence_threshold:.2f}).")
        explanation = "\n".join(explanation_lines)

        packet = Governance_Action_Packet(
            cve_id=intel.cve_id,
            intel=intel,
            asset_criticality=asset_crit,
            recommended_action=rule.get("action", "Log for review."),
            policy_reference=rule.get("policy", "N/A"),
            requires_human=requires_human,
            explanation=explanation,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        return packet


# ---------------------------
# Utility to convert packet -> dict (for logging)
# ---------------------------
def packet_to_log_dict(packet: Governance_Action_Packet, reviewer: Optional[str] = None, final_decision: Optional[str] = None, justification: Optional[str] = None) -> dict:
    base = asdict(packet)
    base["reviewer"] = reviewer
    base["final_decision"] = final_decision
    base["justification"] = justification
    return base


# If run directly, test loading
if __name__ == "__main__":
    engine = GRCEngine()
    # quick smoke test
    dummy_intel = AI_Risk_Intel(
        cve_id="CVE-TEST-000",
        predicted_severity="HIGH",
        confidence=0.72,
        prediction_proba={"CRITICAL": 0.05, "HIGH": 0.72, "MEDIUM": 0.18, "LOW": 0.05},
        key_features={"overflow": 0.42, "cwe-119": 0.13},
        model_version="ml_pipeline_v1.0",
        timestamp=datetime.utcnow().isoformat() + "Z",
    )
    packet = engine.generate_governance_packet(dummy_intel, ["microsoft:windows_server"])
    print(json.dumps(packet_to_log_dict(packet), indent=2))
