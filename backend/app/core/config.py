from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    # Basic App Settings
    PROJECT_NAME: str = "AICDS - AI Cybersecurity System"
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DEBUG: bool = False

    # Standard AI Engine Keys
    GROQ_API_KEY: Optional[str] = None
    GROQ_API_URL: Optional[str] = "https://api.groq.com/openai/v1/chat/completions"
    
    # Intelligence Layer Keys (FraudLens)
    SERPER_API_KEY: Optional[str] = None
    OPENROUTER_API_KEY: Optional[str] = None
    HF_API_KEY: Optional[str] = None
    
    # Webhook & Alert Settings (Moved inside the class)
    WEBHOOK_URL: Optional[str] = None 
    ALERTS_ENABLED: bool = True
    THREAT_THRESHOLD: float = 0.8  # Alert only if confidence > 80%

    # CORS Allowed Origins
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:3000,https://localhost:5173,https://localhost:3000"

    # Network model retraining
    NETWORK_BASE_DATASET_DIR: str = "/opt/pleroma/ml/data/base"  # base capture CSVs
    BENIGN_SAMPLE_RATE: float = 0.02   # fraction of benign flows persisted at ingest
    BENIGN_SAMPLE_CAP: int = 20000     # keep at most this many newest benign samples

    # Network engine decision thresholds (tunable without code changes).
    # NETWORK_ANOMALY_THRESHOLD: IsolationForest decision_function cutoff —
    #   a flow scoring below this is flagged "Anomaly-novel" (→ Suspicious).
    #   Make it more negative to flag fewer flows (see deploy/CAPTURE.md and
    #   backend/anomaly_report.py to choose a value from real data).
    # NETWORK_CONFIDENCE_THRESHOLD: below this top-class probability a
    #   "Malicious" verdict is downgraded to "Suspicious".
    NETWORK_ANOMALY_THRESHOLD: float = -0.05
    NETWORK_CONFIDENCE_THRESHOLD: float = 0.60

    # Pydantic Config
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

# Initialize the settings object
settings = Settings()