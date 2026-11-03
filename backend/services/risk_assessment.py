import os
from typing import Any, Dict


def _read_float(name: str, default: float, minimum: float, maximum: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"{name} harus berupa angka.") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} harus berada di antara {minimum} dan {maximum}.")
    return parsed


class RiskAssessor:
    """
    Combines independent component scores.

    Defaults are explicit, configurable assumptions rather than model claims:
    ML probability is weighted 60%, heuristic score 40%; thresholds are 70
    (PHISHING) and 35 (SUSPICIOUS). A confirmed Web Risk threat is an override.
    """

    def __init__(self) -> None:
        self.ml_weight = _read_float("RISK_ML_WEIGHT", 0.60, 0.0, 1.0)
        self.heuristic_weight = _read_float("RISK_HEURISTIC_WEIGHT", 0.40, 0.0, 1.0)
        if round(self.ml_weight + self.heuristic_weight, 6) != 1.0:
            raise ValueError("RISK_ML_WEIGHT + RISK_HEURISTIC_WEIGHT harus sama dengan 1.")
        self.phishing_threshold = _read_float("RISK_PHISHING_THRESHOLD", 70.0, 0.0, 100.0)
        self.suspicious_threshold = _read_float("RISK_SUSPICIOUS_THRESHOLD", 35.0, 0.0, 100.0)
        if self.suspicious_threshold >= self.phishing_threshold:
            raise ValueError("RISK_SUSPICIOUS_THRESHOLD harus lebih kecil dari RISK_PHISHING_THRESHOLD.")

    def assess(
        self,
        ml_result: Dict[str, Any],
        heuristic_result: Dict[str, Any],
        threat_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        ml_score = float(ml_result.get("probabilities", {}).get("phishing", 0.0)) * 100
        heuristic_score = float(heuristic_result.get("risk_score", 0.0))
        combined_score = round(
            (ml_score * self.ml_weight) + (heuristic_score * self.heuristic_weight)
        )

        threat_status = threat_result.get("status")
        if threat_status == "THREAT_DETECTED":
            combined_score = max(combined_score, 90)
            final_status = "PHISHING"
        elif combined_score >= self.phishing_threshold:
            final_status = "PHISHING"
        elif combined_score >= self.suspicious_threshold:
            final_status = "SUSPICIOUS"
        else:
            final_status = "SAFE"

        conflicts = []
        if ml_result.get("status") == "PHISHING" and heuristic_result.get("status") == "SAFE":
            conflicts.append("ML mendeteksi phishing, tetapi heuristik tidak menemukan indikator kuat.")
        if ml_result.get("status") == "LEGITIMATE" and heuristic_result.get("status") == "PHISHING":
            conflicts.append("ML mengklasifikasikan legitimate, tetapi heuristik mendeteksi indikator phishing.")
        if threat_status in {"UNAVAILABLE", "ERROR"}:
            conflicts.append("Threat Intelligence tidak tersedia; hasil akhir tidak menggunakan konfirmasi provider.")

        return {
            "final_status": final_status,
            "risk_score": int(max(0, min(100, combined_score))),
            "component_scores": {
                "machine_learning": round(ml_score, 2),
                "heuristic": round(heuristic_score, 2),
            },
            "configuration": {
                "machine_learning_weight": self.ml_weight,
                "heuristic_weight": self.heuristic_weight,
                "phishing_threshold": self.phishing_threshold,
                "suspicious_threshold": self.suspicious_threshold,
            },
            "conflicts": conflicts,
        }


risk_assessor = RiskAssessor()
