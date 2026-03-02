import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import proteus
from typing import Tuple, Optional


class ProteusMLTrainer:
    def __init__(self):
        self.rf_model = RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=42, n_jobs=-1
        )
        self.isolation_model = IsolationForest(
            contamination=0.1, random_state=42, n_jobs=-1
        )

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

            return np.array(features)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            error_msg = str(e)
            # Expected errors - silently skip
            if any(
                x in error_msg
                for x in [
                    "Unsupported file type",
                    "bad offset",
                    "bad magic",
                    "bad input",
                    "invalid utf8",
                    "Invalid PE",
                    "Invalid ELF",
                    "Malformed entity",
                    "Unable to extract",
                    "Cannot find name from rva",
                    "Probably cert_size",
                ]
            ):
                return None
            # Unexpected errors - log them
            else:
                print(f"[!] Unexpected error in {Path(file_path).name}: {e}")
                return None

    def prepare_dataset(
        self, malicious_dir: str, clean_dir: str
    ) -> Tuple[np.ndarray, np.ndarray]:
        X = []
        y = []

        skipped_reasons = {"unsupported": 0, "corrupted": 0, "other": 0}
        processed = 0

        print("[*] Processing malicious samples...")
        mal_path = Path(malicious_dir)
        if mal_path.exists():
            mal_files = list(mal_path.glob("**/*.*"))
            mal_files = [
                f for f in mal_files if f.suffix.lower() in [".exe", ".dll", ".malware"]
            ]

            total_files = len(mal_files)
            print(f"    Found {total_files} malware files")

            for idx, file in enumerate(mal_files, 1):
                try:
                    features = self.extract_features(str(file))
                    if features is not None:
                        X.append(features)
                        y.append(1)
                        processed += 1
                        if processed % 20 == 0:
                            print(
                                f"    Progress: {processed}/{total_files} processed..."
                            )
                    else:
                        file_bytes = file.read_bytes()[:4] if file.exists() else b""
                        if file_bytes[:2] == b"PK":
                            skipped_reasons["corrupted"] += 1
                        elif file_bytes[:2] in [b"MZ", b"\x7fELF"]:
                            skipped_reasons["corrupted"] += 1
                        else:
                            skipped_reasons["unsupported"] += 1
                except KeyboardInterrupt:
                    raise
                except Exception:
                    skipped_reasons["other"] += 1

            print("\n    [+] Malicious samples:")
            print(f"        Processed: {processed}")
            print(
                f"        Skipped - Unsupported format: {skipped_reasons['unsupported']}"
            )
            print(
                f"        Skipped - Corrupted/Invalid: {skipped_reasons['corrupted']}"
            )
            if skipped_reasons["other"] > 0:
                print(f"        Skipped - Other errors: {skipped_reasons['other']}")
        else:
            print(f"[!] Malicious directory not found: {malicious_dir}")

        print("\n[*] Processing clean samples...")
        clean_path = Path(clean_dir)
        if clean_path.exists():
            clean_files = list(clean_path.glob("**/*.exe"))
            clean_processed = 0
            clean_skipped = 0
            total_clean = len(clean_files)
            print(f"    Found {total_clean} clean files")

            for idx, file in enumerate(clean_files, 1):
                try:
                    features = self.extract_features(str(file))
                    if features is not None:
                        X.append(features)
                        y.append(0)
                        clean_processed += 1
                        if clean_processed % 100 == 0:
                            print(
                                f"    Progress: {clean_processed}/{total_clean} processed..."
                            )
                    else:
                        clean_skipped += 1
                except KeyboardInterrupt:
                    raise
                except Exception:
                    clean_skipped += 1

            print("\n    [+] Clean samples:")
            print(f"        Processed: {clean_processed}")
            if clean_skipped > 0:
                print(f"        Skipped: {clean_skipped}")
        else:
            print(f"[!] Clean directory not found: {clean_dir}")

        return np.array(X), np.array(y)

    def train_random_forest(self, X: np.ndarray, y: np.ndarray):
        print("\n[*] Training Random Forest Classifier...")

        if len(X) < 10:
            print("[!] Too few samples")
            return

        unique, counts = np.unique(y, return_counts=True)
        print(f"[*] Class distribution: {dict(zip(unique, counts))}")

        if len(unique) < 2:
            print("[!] Only one class in dataset. Cannot train classifier.")
            print("[!] Need both malicious and clean samples.")
            print("[!] Run: python test_dataset_builder.py")
            return

        if np.min(counts) < 2:
            print("[!] Warning: Very imbalanced dataset.")
            print("[!] Training on full dataset without test split.")

            self.rf_model.fit(X, y)
            train_score = self.rf_model.score(X, y)
            print(f"[+] Training accuracy: {train_score:.4f}")

            print("\n[!] Need more samples for proper evaluation")
            print("[!] Consider running: python test_dataset_builder.py")
            return

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        self.rf_model.fit(X_train, y_train)

        train_score = self.rf_model.score(X_train, y_train)
        test_score = self.rf_model.score(X_test, y_test)

        print(f"[+] Training accuracy: {train_score:.4f}")
        print(f"[+] Test accuracy: {test_score:.4f}")

        cv_scores = cross_val_score(self.rf_model, X, y, cv=min(5, np.min(counts)))
        print(f"[+] Cross-validation scores: {cv_scores}")
        print(
            f"[+] Mean CV score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})"
        )

        y_pred = self.rf_model.predict(X_test)

        unique_test = np.unique(y_test)
        if len(unique_test) == 2:
            target_names = ["Clean", "Malicious"]
        elif 1 in unique_test:
            target_names = ["Malicious"]
        else:
            target_names = ["Clean"]

        print("\n[*] Classification Report:")
        print(
            classification_report(
                y_test, y_pred, target_names=target_names, zero_division=0
            )
        )

        print("\n[*] Confusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        if cm.shape == (2, 2):
            print(f"    TN: {cm[0][0]}, FP: {cm[0][1]}")
            print(f"    FN: {cm[1][0]}, TP: {cm[1][1]}")
        else:
            print(f"    {cm}")

        feature_names = [
            "entropy",
            "threat_score",
            "suspicious_indicators",
            "import_count",
            "export_count",
            "section_count",
            "max_section_entropy",
            "total_strings",
            "urls",
            "ips",
            "registry_keys",
            "suspicious_strings",
            "file_paths",
            "encoded_strings",
            "encoded_ratio",
            "suspicious_ratio",
        ]

        importances = self.rf_model.feature_importances_
        indices = np.argsort(importances)[::-1]

        print("\n[*] Feature Importances:")
        for i in range(min(10, len(indices))):
            print(f"    {feature_names[indices[i]]}: {importances[indices[i]]:.4f}")

        return X_test, y_test, y_pred

    def train_isolation_forest(self, X: np.ndarray):
        print("\n[*] Training Isolation Forest (Anomaly Detection)...")
        self.isolation_model.fit(X)
        print("[+] Isolation Forest trained successfully")

    def save_models(
        self,
        rf_path: str = "models/rf_model.pkl",
        iso_path: str = "models/iso_model.pkl",
    ):
        Path("models").mkdir(exist_ok=True)

        with open(rf_path, "wb") as f:
            pickle.dump(self.rf_model, f)
        print(f"[+] Random Forest saved to {rf_path}")

        with open(iso_path, "wb") as f:
            pickle.dump(self.isolation_model, f)
        print(f"[+] Isolation Forest saved to {iso_path}")

    def load_models(
        self,
        rf_path: str = "models/rf_model.pkl",
        iso_path: str = "models/iso_model.pkl",
    ):
        with open(rf_path, "rb") as f:
            self.rf_model = pickle.load(f)
        print(f"[+] Random Forest loaded from {rf_path}")

        with open(iso_path, "rb") as f:
            self.isolation_model = pickle.load(f)
        print(f"[+] Isolation Forest loaded from {iso_path}")


def main():
    print("===========================================")
    print("   PROTEUS ML Training Pipeline")
    print("===========================================\n")

    trainer = ProteusMLTrainer()

    # Try real malware dataset first (collected from MalwareBazaar)
    malicious_dir = "dataset/malicious"
    clean_dir = "dataset/clean"

    # Fallback to test_dataset if real malware not available
    if not Path(malicious_dir).exists():
        print("[!] Real malware dataset not found, using synthetic test_dataset")
        malicious_dir = "test_dataset/malicious"
        clean_dir = "test_dataset/clean"

    # Verify at least one directory exists
    if not Path(malicious_dir).exists() and not Path(clean_dir).exists():
        print("[!] ERROR: No dataset directories found!")
        print("[!] Tried:")
        print("    - dataset/malicious (real malware)")
        print("    - test_dataset/malicious (synthetic)")
        print("\n[*] Solution:")
        print("    1. Collect real malware: python malware_collector.py")
        print("    2. Or build test dataset: python test_dataset_builder.py")
        return

    print("[*] Using directories:")
    print(f"    Malicious: {malicious_dir}")
    print(f"    Clean: {clean_dir}\n")

    X, y = trainer.prepare_dataset(malicious_dir, clean_dir)

    print("\n[*] Dataset Summary:")
    print(f"    Total samples: {len(X)}")
    print(f"    Malicious: {np.sum(y == 1)}")
    print(f"    Clean: {np.sum(y == 0)}")

    if len(X) > 0:
        print(f"    Features: {X.shape[1]}")

    if len(X) < 10:
        print("\n[!] Warning: Dataset too small for reliable training")
        print("[!] Recommendation: Add more samples (50+ each class)")
        return

    if np.sum(y == 1) == 0:
        print("\n[!] ERROR: No malicious samples found!")
        print("[!] Run: python test_dataset_builder.py")
        return

    trainer.train_random_forest(X, y)
    trainer.train_isolation_forest(X)
    trainer.save_models()

    print("\n[+] Training complete!")

    if np.sum(y == 1) < 50:
        print("\n[*] Recommendation: For better accuracy, collect more samples")


if __name__ == "__main__":
    main()
