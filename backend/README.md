# 🛡️ AICDS – AI Cybersecurity & Threat Detection System

An AI-assisted cybersecurity system designed to detect, analyze, and respond to modern cyber threats using a hybrid approach combining rule-based detection and machine learning.

---

## 🚀 Overview

AICDS (AI Cybersecurity & Detection System) is built to address the growing complexity of cyber threats by integrating intelligent analysis into traditional detection pipelines.

The system processes incoming data (logs, payloads, requests) and applies both **rule-based logic** and **AI-driven anomaly detection** to identify malicious activity in real time.

---

## ⚠️ Problem

Traditional security systems:

* Rely heavily on static rules and signatures
* Struggle with zero-day and evolving attacks
* Generate high false positives

AICDS introduces adaptive intelligence to improve detection accuracy and response speed.

---

## 💡 Solution

A hybrid detection pipeline that includes:

* ✅ Rule-based threat detection (known attack patterns)
* 🤖 AI anomaly detection (unknown / evolving threats)
* 🔄 Real-time data ingestion and processing
* 📡 API-based architecture for scalability

---

## 🧠 System Architecture

```
Incoming Data (Logs / Requests / Payloads)
            ↓
   Data Ingestion Layer
            ↓
   Preprocessing & Parsing
            ↓
 ┌──────────────────────────┐
 │  Rule-Based Engine       │
 │  (Signatures, Patterns)  │
 └──────────────────────────┘
            ↓
 ┌──────────────────────────┐
 │  AI Detection Engine     │
 │  (Anomaly Detection)     │
 └──────────────────────────┘
            ↓
   Threat Classification
            ↓
   Response / Alert System
```

---

## 🛠️ Tech Stack

* **Backend Framework:** FastAPI
* **Language:** Python 3.11+
* **ORM:** SQLAlchemy
* **Database:** PostgreSQL
* **Web Server:** Gunicorn + Uvicorn Workers
* **AI/ML:** Scikit-learn
* **Data Processing:** Pandas, NumPy
* **Security:** Bcrypt, Python-Jose (JWT)
* **API Documentation:** Swagger/OpenAPI (built-in with FastAPI)

---

## 🔧 Environment Variables

Create a `.env` file in the project root:

```env
# Database (auto-set by Render if using Render PostgreSQL)
DATABASE_URL=postgresql://user:password@localhost:5432/aicds

# External API Keys
GROQ_API_KEY=your_groq_api_key_here
SERPER_API_KEY=your_serper_api_key_here
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Optional: Python version (for Render)
PYTHON_VERSION=3.11.0
```

For local development, copy from `.env.example` (if available) or use the template above.

---

## 🔍 Features

* Real-time threat detection
* Hybrid detection (rules + AI)
* Modular microservice-friendly architecture
* API endpoints for integration
* Scalable backend design

---

## 📡 API Example

```bash
POST /analyze

{
  "payload": "SELECT * FROM users WHERE id = '1' OR '1'='1'"
}
```

### Response:

```json
{
  "threat_detected": true,
  "type": "SQL Injection",
  "confidence": 0.92
}
```

---

## 🧪 Use Cases

* Web application security
* API traffic monitoring
* Fraud detection systems
* Security research and experimentation

---

## 📈 Future Improvements

* Deep learning-based detection models
* Integration with SIEM systems
* Real-time dashboard for monitoring
* Automated response mechanisms

---

## ⚙️ Installation

### Prerequisites
- Python 3.11+
- pip or poetry
- PostgreSQL (for production)

### Local Setup

```bash
git clone https://github.com/Ola-09/aicds-backend-main.git
cd aicds-backend-main
pip install -r requirements.txt
```

### Running Locally

```bash
# Development (with auto-reload)
uvicorn app.main:app --reload

# Production simulation
gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app
```

The API will be available at `http://localhost:8000/`

---

## 🚀 Deployment

### Render Deployment

This project is configured for deployment on [Render](https://render.com/).

#### Prerequisites
- GitHub repository with this code
- Render account (free tier available)

#### Automatic Deployment Setup

1. **Connect Repository to Render**
   - Go to [Render Dashboard](https://dashboard.render.com)
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Select the `aicds-backend` repository

2. **Configure Service**
   - **Name**: `aicds-backend`
   - **Environment**: Python 3
   - **Region**: Choose closest to your users
   - **Branch**: main
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app`

3. **Set Environment Variables**
   In the Render dashboard, add:
   ```
   DATABASE_URL=<your-postgresql-url>
   PYTHON_VERSION=3.11.0
   GROQ_API_KEY=<your-groq-api-key>
   SERPER_API_KEY=<your-serper-api-key>
   OPENROUTER_API_KEY=<your-openrouter-api-key>
   ```

4. **Database Setup**
   - Render automatically provisions a PostgreSQL database
   - The `DATABASE_URL` is set as an environment variable
   - Migrations run automatically on deployment

#### Deploy Using render.yaml

The project includes a `render.yaml` file for Infrastructure as Code (IaC) deployment:

```bash
# Deploy using render.yaml
# Simply push to your repository and Render will detect render.yaml
# No manual configuration needed!
```

#### After Deployment
- API endpoint: `https://aicds-backend.onrender.com`
- Update frontend `API_BASE_URL` to point to this URL
- Monitor logs in Render dashboard

---

## 📌 Status

🚧 Actively under development
This project is continuously being improved with new detection capabilities and optimizations.

---

## 🤝 Contributing

Contributions, ideas, and feedback are welcome.

---

## 📬 Contact

Ajiboye Olalekan
Email: [olalekanajiboye697@gmail.com](mailto:olalekanajiboye697@gmail.com)

---

## ⭐ Final Note

This project reflects my interest in combining **Artificial Intelligence and Cybersecurity** to build adaptive, intelligent defense systems for modern digital environments.
