"""NetworkEngine — CIC-IDS2018 RandomForest classifier.

Replaces the original NSL-KDD-based engine. Loads four artifacts:
    model.joblib            — RandomForestClassifier
    scaler.joblib           — StandardScaler fit on training data
    label_encoder.joblib    — LabelEncoder mapping class index → CIC label
    feature_names.joblib    — ordered list[str] of expected input columns

If any artifact is missing, falls back to mock mode (returns Error verdict)
so the rest of the backend (URL scanner, auth, logs) keeps running.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import joblib
import numpy as np
import pandas as pd

from app.core.config import settings

# Map model output (raw CIC class names) to the 3-tier verdict the
# frontend understands. Web-attack classes go to "Suspicious" rather
# than "Malicious" because their precision on the held-out test set
# was ~5% — most positives are false positives, so we let them through
# as "review required" instead of "block".
VERDICT_MAPPING: dict[str, str] = {
    "Benign": "Normal",
    "Bot": "Malicious",
    "DoS attacks-Hulk": "Malicious",
    "DoS attacks-GoldenEye": "Malicious",
    "DoS attacks-Slowloris": "Malicious",
    "DoS attacks-SlowHTTPTest": "Malicious",
    "Brute Force -Web": "Suspicious",
    "Brute Force -XSS": "Suspicious",
    "SQL Injection": "Suspicious",
}

# Below this top-class probability, downgrade "Malicious" → "Suspicious"
# so low-confidence predictions don't trigger block-tier alerts.
CONFIDENCE_THRESHOLD = 0.60


class NetworkEngine:
    def __init__(self) -> None:
        self.base_dir = Path(__file__).resolve().parent
        self.data_dir = self.base_dir / "data"

        self.model_path = self.data_dir / "model.joblib"
        self.scaler_path = self.data_dir / "scaler.joblib"
        self.encoder_path = self.data_dir / "label_encoder.joblib"
        self.features_path = self.data_dir / "feature_names.joblib"

        self.model: Any = None
        self.scaler: Any = None
        self.encoder: Any = None
        self.feature_names: list[str] = []
        self.is_mock: bool = True

        self.load_artifacts()

    def load_artifacts(self) -> None:
        """Load model/scaler/encoder/feature_names from data_dir.

        On any failure, sets is_mock=True so the backend still boots —
        the URL scanner doesn't depend on this engine.
        """
        required = [
            self.model_path,
            self.scaler_path,
            self.encoder_path,
            self.features_path,
        ]
        missing = [p.name for p in required if not p.exists()]
        if missing:
            print(
                f"⚠️ NetworkEngine: missing artifacts {missing} in "
                f"{self.data_dir}. Using mock mode."
            )
            self.is_mock = True
            return

        try:
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            self.encoder = joblib.load(self.encoder_path)
            self.feature_names = list(joblib.load(self.features_path))
            self.is_mock = False
            print(
                f"✅ NetworkEngine: CIC-IDS2018 RF loaded "
                f"({len(self.feature_names)} features, "
                f"{len(self.encoder.classes_)} classes)"
            )
        except Exception as exc:
            print(f"❌ NetworkEngine: load failed: {exc}")
            self.is_mock = True

    def preprocess(self, record: dict) -> np.ndarray:
        """Build a feature row in the model's expected column order.

        Missing CIC features default to 0.0 — this is deliberate. The
        manual frontend form submits NSL-KDD-shaped fields that don't
        match CIC names; predictions on those inputs will be poor.
        Real-quality predictions arrive in Phase 4 when the sensor
        ships CICFlowMeter-extracted feature vectors directly.
        """
        full_vector: dict[str, float] = {name: 0.0 for name in self.feature_names}
        for key, val in record.items():
            if key in full_vector:
                try:
                    full_vector[key] = float(val)
                except (TypeError, ValueError):
                    full_vector[key] = 0.0

        # DataFrame ensures the scaler sees columns in the exact training
        # order regardless of dict iteration order.
        df = pd.DataFrame([full_vector], columns=self.feature_names)
        return self.scaler.transform(df)

    def predict(self, record: dict) -> tuple[str, float, str]:
        """Run inference. Returns (verdict, confidence, raw_class).

        verdict       — "Normal" | "Suspicious" | "Malicious" | "Error"
        confidence    — top-class probability in [0, 1]
        raw_class     — the underlying CIC label (e.g. "DoS attacks-Hulk")
        """
        if self.is_mock:
            return "Error", 0.0, "MOCK_MODE"

        try:
            X = self.preprocess(record)
            pred_idx = int(self.model.predict(X)[0])
            probs = self.model.predict_proba(X)[0]
            confidence = float(np.max(probs))

            raw_class = str(self.encoder.inverse_transform([pred_idx])[0])
            verdict = VERDICT_MAPPING.get(raw_class, "Suspicious")

            # Curb false-positive Malicious alerts from low-confidence calls.
            if verdict == "Malicious" and confidence < CONFIDENCE_THRESHOLD:
                verdict = "Suspicious"

            return verdict, confidence, raw_class
        except Exception as exc:
            print(f"❌ NetworkEngine prediction error: {exc}")
            return "Error", 0.0, "ERROR"

    async def get_ai_interpretation(
        self,
        record: dict,
        verdict: str,
        confidence: float,
        raw_class: str,
    ) -> str:
        """Optional one-sentence LLM explanation for the verdict.

        Falls back to a generic message if GROQ_API_KEY isn't set or
        the API call errors. The LLM sees the raw CIC class so it can
        comment on the specific attack family the model picked.
        """
        if not settings.GROQ_API_KEY:
            return (
                f"Pattern matched {raw_class} signature "
                f"(confidence {confidence * 100:.0f}%)."
            )

        # Keep the prompt focused — passing all 78 features is noise.
        # The most informative columns for human interpretation are the
        # flow-shape signals (duration, packet counts, error rates, port).
        salient_keys = [
            "Dst Port", "Protocol", "Flow Duration",
            "Tot Fwd Pkts", "Tot Bwd Pkts",
            "TotLen Fwd Pkts", "TotLen Bwd Pkts",
            "Flow Byts/s", "Flow Pkts/s",
            "SYN Flag Cnt", "RST Flag Cnt", "ACK Flag Cnt",
        ]
        salient = {k: record.get(k) for k in salient_keys if k in record}

        prompt = f"""You are a Senior SOC analyst. A CIC-IDS2018-trained RandomForest classifier produced:

Predicted class : {raw_class}
Verdict tier    : {verdict}
Confidence      : {confidence * 100:.1f}%

Salient flow features:
{json.dumps(salient, indent=2)}

In ONE technical sentence, describe what this flow plausibly represents and whether the verdict looks right. Be blunt — if the features contradict the verdict, say so."""

        headers = {
            "Authorization": f"Bearer {settings.GROQ_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 150,
        }

        async with httpx.AsyncClient() as client:
            try:
                res = await client.post(
                    settings.GROQ_API_URL,
                    headers=headers,
                    json=payload,
                    timeout=10.0,
                )
                return res.json()["choices"][0]["message"]["content"].strip()
            except Exception as exc:
                print(f"⚠️ AI interpretation failed: {exc}")
                return f"Pattern matched {raw_class} signature."
