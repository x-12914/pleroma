import joblib
import pandas as pd
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from app.db.database import SessionLocal
from app.db.models import DetectionLog, Feedback

# Paths - These must match where engine.py looks for data
BASE_DIR = os.path.dirname(__file__)
DATA_PATH = os.path.join(BASE_DIR, "data", "KDDTrain+.txt")
MODEL_PATH = os.path.join(BASE_DIR, "data", "model.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "data", "scaler.joblib")
ENCODER_PATH = os.path.join(BASE_DIR, "data", "encoders.joblib")

# NSL-KDD 43-column structure
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", 
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", 
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", 
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", 
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", 
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", 
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"
]

def load_feedback_examples():
    feedback_rows = []
    port_map = {
        22: "ssh",
        23: "telnet",
        80: "http",
        443: "http_443",
        21: "ftp",
        25: "smtp",
        53: "domain"
    }

    with SessionLocal() as db:
        entries = (
            db.query(Feedback)
            .join(DetectionLog)
            .filter(Feedback.is_correct == True)
            .filter(DetectionLog.category == "NETWORK_TRAFFIC")
            .all()
        )

        for entry in entries:
            raw_input = (entry.log.report_data or {}).get("raw_input") or {}
            if not raw_input:
                continue

            sample = {col: 0 for col in COLUMNS}
            sample["difficulty_level"] = 0
            sample["protocol_type"] = raw_input.get("protocol_type") or raw_input.get("protocol")
            sample["service"] = raw_input.get("service")
            sample["flag"] = raw_input.get("flag")
            sample["src_bytes"] = raw_input.get("src_bytes", 0)
            sample["dst_bytes"] = raw_input.get("dst_bytes", 0)
            sample["count"] = raw_input.get("count", 0)
            sample["srv_count"] = raw_input.get("srv_count", 0)
            sample["serror_rate"] = raw_input.get("serror_rate", 0.0)
            sample["srv_serror_rate"] = raw_input.get("srv_serror_rate", 0.0)
            sample["rerror_rate"] = raw_input.get("rerror_rate", 0.0)
            sample["srv_rerror_rate"] = raw_input.get("srv_rerror_rate", 0.0)
            sample["same_srv_rate"] = raw_input.get("same_srv_rate", 0.0)
            sample["diff_srv_rate"] = raw_input.get("diff_srv_rate", 0.0)
            sample["dst_port"] = raw_input.get("dst_port")

            if sample["dst_port"] and not sample["service"]:
                sample["service"] = port_map.get(sample["dst_port"], "other")

            if raw_input.get("service") == "ssh" or raw_input.get("dst_port") == 22:
                sample["logged_in"] = 1

            label = (entry.corrected_verdict or "").strip().lower()
            if label == "normal":
                sample["label"] = "normal."
            else:
                sample["label"] = "neptune."

            feedback_rows.append(sample)

    return feedback_rows


def perform_retraining():
    """Logic to retrain the model and update local artifacts."""
    print("🚀 ML Engine: Starting retraining process...")
    
    if not os.path.exists(DATA_PATH):
        print(f"❌ Error: Dataset not found at {DATA_PATH}")
        return

    try:
        # 1. Load Data
        df = pd.read_csv(DATA_PATH, header=None, names=COLUMNS)
        
        # 2. Pull new real-world labeled examples from Neon feedback
        feedback_examples = load_feedback_examples()
        if feedback_examples:
            feedback_df = pd.DataFrame(feedback_examples)
            df = pd.concat([df, feedback_df], ignore_index=True)
            print(f"✅ Added {len(feedback_examples)} feedback examples to retraining data.")
        else:
            print("ℹ️ No feedback examples found for retraining.")

        # Drop the difficulty level (not used for feature detection)
        df.drop("difficulty_level", axis=1, inplace=True)
        
        # 3. Preprocessing Categorical Columns
        categorical_cols = ["protocol_type", "service", "flag"]
        encoders = {}

        for col in categorical_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            encoders[col] = le

        # 4. Split Features and Target
        X = df.drop("label", axis=1)
        y = df["label"]

        # 5. Scaling
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # 6. Training
        print("🧠 Training Random Forest model...")
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_scaled, y)

        # 7. Save Artifacts to the network/data folder
        joblib.dump(model, MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)
        joblib.dump(encoders, ENCODER_PATH)
        print(f"💾 Artifacts saved to {MODEL_PATH}")

        # 8. Hot-Reload the Engine
        # We import here to avoid circular imports at the top of the file
        from app.services.analysis_service import network_engine
        network_engine.load_artifacts()

        print("✨ ML Engine: Retraining process complete and artifacts hot-reloaded!")

    except Exception as e:
        print(f"❌ ML Engine: Retraining failed: {str(e)}")


if __name__ == "__main__":
    perform_retraining()
