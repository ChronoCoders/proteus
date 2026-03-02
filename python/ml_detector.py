import numpy as np
import pickle
from pathlib import Path
from typing import Optional, Dict, Any
import proteus


class ProteusMLDetector:
    def __init__(self):
        self.rf_model = None
        self.isolation_model = None

    def load_model(
        self,
        rf_path: str = "models/rf_model.pkl",
        iso_path: str = "models/iso_model.pkl",
    ) -> None:
        rf_file = Path(rf_path)
        iso_file = Path(iso_path)

        if rf_file.exists():
            try:
                with open(rf_path, "rb") as f:
                    self.rf_model = pickle.load(f)
                print(f"[+] Random Forest loaded from {rf_path}")
            except (pickle.UnpicklingError, EOFError) as e:
                print(f"[!] Failed to load RF model: {e}")
        else:
            print(f"[!] Model not found: {rf_path}")

        if iso_file.exists():
            try:
                with open(iso_path, "rb") as f:
                    self.isolation_model = pickle.load(f)
                print(f"[+] Isolation Forest loaded from {iso_path}")
            except (pickle.UnpicklingError, EOFError) as e:
                print(f"[!] Failed to load Isolation model: {e}")
        else:
            print(f"[!] Model not found: {iso_path}")

    def extract_features(self, file_path: str) -> Optional[np.ndarray]:
        try:
            analysis = proteus.analyze_file(file_path)
            strings = proteus.extract_strings_from_file(file_path)

            features = [
                analysis.entropy,
                analysis.threat_score,
                len(analysis.suspicious_indicators),
                analysis.import_count,
                analysis.export_count,
                analysis.section_count,
                analysis.max_section_entropy,
                strings.total_strings,
                len(strings.urls),
                len(strings.ips),
                len(strings.registry_keys),
                len(strings.suspicious_strings),
                len(strings.file_paths),
                strings.encoded_strings,
                strings.encoded_strings / max(strings.total_strings, 1),
                len(strings.suspicious_strings) / max(strings.total_strings, 1),
            ]

            return np.array(features).reshape(1, -1)
        except (AttributeError, ValueError, RuntimeError) as e:
            print(f"[!] Error extracting features: {e}")
            return None

    def predict(self, file_path: str) -> Dict[str, Any]:
        if self.rf_model is None:
            return {
                "prediction": "unknown",
                "confidence": 0.0,
                "anomaly_score": 0.0,
                "error": "Model not loaded",
            }

        features = self.extract_features(file_path)

        if features is None:
            return {
                "prediction": "error",
                "confidence": 0.0,
                "anomaly_score": 0.0,
                "error": "Feature extraction failed",
            }

        try:
            rf_prediction = self.rf_model.predict(features)[0]
            rf_proba = self.rf_model.predict_proba(features)[0]
        except (ValueError, AttributeError) as e:
            return {
                "prediction": "error",
                "confidence": 0.0,
                "anomaly_score": 0.0,
                "error": f"Prediction failed: {e}",
            }

        anomaly_score = 0.0
        if self.isolation_model is not None:
            try:
                self.isolation_model.predict(features)[0]
                anomaly_score = self.isolation_model.score_samples(features)[0]
            except (ValueError, AttributeError):
                pass

        result = {
            "prediction": "malicious" if rf_prediction == 1 else "clean",
            "confidence": float(max(rf_proba)),
            "probabilities": {
                "clean": float(rf_proba[0]),
                "malicious": float(rf_proba[1]) if len(rf_proba) > 1 else 0.0,
            },
            "anomaly_score": float(anomaly_score),
            "is_anomaly": bool(anomaly_score < -0.5),
        }

        return result
