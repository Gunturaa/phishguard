import os
import pickle
import logging
import warnings
import joblib
import numpy as np
from typing import Dict, Any, List, Union

# Suppress UserWarning dari sklearn terkait feature names pada array numpy
warnings.filterwarnings("ignore", message=".*X does not have valid feature names.*")

logger = logging.getLogger("phishguard.ml_detector")

class MLDetector:
    """
    Service untuk mendeteksi potensi Phishing URL menggunakan Model Machine Learning Random Forest.
    Model dilatih menggunakan dataset LegitPhish (100k+ data) dengan 16 fitur URL.
    Label:
      - 0: PHISHING
      - 1: LEGITIMATE
    """

    def __init__(self, model_path: str = None, features_path: str = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.model_path = model_path or os.path.join(base_dir, "models", "phishguard_model.pkl")
        self.features_path = features_path or os.path.join(base_dir, "models", "phishguard_features.pkl")
        self.model = None
        self.feature_names = []
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Memuat model Random Forest dan daftar urutan nama fitur."""
        try:
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"File model tidak ditemukan di: {self.model_path}")
            if not os.path.exists(self.features_path):
                raise FileNotFoundError(f"File fitur tidak ditemukan di: {self.features_path}")

            with open(self.features_path, "rb") as f:
                self.feature_names = pickle.load(f)

            self.model = joblib.load(self.model_path)
            logger.info("Model Random Forest & fitur berhasil dimuat (%d fitur).", len(self.feature_names))
        except Exception as e:
            logger.error("Gagal memuat model Machine Learning: %s", str(e), exc_info=True)
            self.model = None
            self.feature_names = []

    def is_ready(self) -> bool:
        """Memeriksa apakah model siap digunakan untuk inferensi."""
        return self.model is not None and len(self.feature_names) > 0

    def predict(self, features: Union[Dict[str, Any], List[float]]) -> Dict[str, Any]:
        """
        Menghasilkan prediksi keamanan URL dari fitur input.
        
        Args:
            features: Dictionary nama_fitur -> nilai, atau list numerik dengan urutan tepat 16 fitur.
        
        Returns:
            Dict berisi status, confidence, dan probabilitas tiap kelas.
        """
        if not self.is_ready():
            return {
                "status": "UNAVAILABLE",
                "predicted_class": None,
                "confidence": 0.0,
                "probabilities": {
                    "phishing": 0.0,
                    "legitimate": 0.0
                },
                "error": "Model ML belum siap atau gagal dimuat.",
                "model_loaded": False
            }

        try:
            # Jika input berupa dictionary, urutkan sesuai self.feature_names
            if isinstance(features, dict):
                feature_vector = [features.get(name, 0.0) for name in self.feature_names]
            elif isinstance(features, (list, tuple)):
                if len(features) != len(self.feature_names):
                    raise ValueError(
                        f"Jumlah fitur tidak cocok. Diharapkan {len(self.feature_names)}, diterima {len(features)}"
                    )
                feature_vector = list(features)
            else:
                raise TypeError("Format fitur harus berupa dict atau list/tuple.")

            # Inferensi menggunakan Random Forest
            X = np.array([feature_vector], dtype=float)
            prediction = int(self.model.predict(X)[0])
            
            # Ambil probabilitas kelas [P(Phishing=0), P(Legitimate=1)]
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X)[0]
                phishing_prob = float(probs[0])
                legitimate_prob = float(probs[1]) if len(probs) > 1 else (1.0 - phishing_prob)
            else:
                phishing_prob = 1.0 if prediction == 0 else 0.0
                legitimate_prob = 1.0 - phishing_prob

            status = "PHISHING" if prediction == 0 else "LEGITIMATE"
            confidence = phishing_prob if prediction == 0 else legitimate_prob

            return {
                "status": status,
                "predicted_class": prediction,
                "confidence": round(confidence, 4),
                "probabilities": {
                    "phishing": round(phishing_prob, 4),
                    "legitimate": round(legitimate_prob, 4)
                },
                "feature_count": len(self.feature_names),
                "model_loaded": True
            }

        except Exception as err:
            logger.error("Terjadi kesalahan saat inferensi ML: %s", str(err), exc_info=True)
            return {
                "status": "ERROR",
                "predicted_class": None,
                "confidence": 0.0,
                "probabilities": {
                    "phishing": 0.0,
                    "legitimate": 0.0
                },
                "error": str(err),
                "model_loaded": True
            }

# Singleton instance untuk digunakan di backend
ml_detector = MLDetector()
