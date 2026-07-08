# 🛡️ SentinelAI — Hybrid Network Intrusion Detection System

> An enterprise-grade Security Operations Center (SOC) dashboard powered by **IBM Watson Machine Learning**, **IBM Watsonx.ai (Granite)**, and **Gradio**.

---

## ✨ Features

| Feature | Description |
|---|---|
| **📡 Live Packet Interception** | Simulates live network traffic monitoring using KDDCup99 signature datasets |
| **🔍 ML Threat Detection** | AutoAI pipeline analyzing 41 distinct network features for anomalies |
| **🤖 Agentic SOC Analyst** | IBM Granite-powered AI that generates automated mitigation playbooks |
| **🎛️ Manual Telemetry** | Override capabilities to manually test destination ports and error rates |
| **📊 Threat Scoring** | Dynamic severity scoring and mathematical boundary explanations |
| **⚡ Throttled Architecture** | Built-in failover and request throttling for IBM Cloud Lite tier stability |

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/NetworkSentinelAI.git
cd NetworkSentinelAI

```

### 2. Install dependencies

```bash
pip install -r requirements.txt

```

### 3. Configure IBM Credentials

Edit the `.env` file in the root directory:

```env
IBM_API_KEY = your_actual_ibm_api_key
PROJECT_ID = your_actual_project_id
WML_ENDPOINT_URL = https://us-south.ml.cloud.ibm.com...

```

> **Get credentials:** [IBM Cloud Console](https://cloud.ibm.com) → Watsonx.ai → Project → Manage → API Keys

### 4. Run the app

```bash
python src/app.py

```

---

## 🔧 Customising the Agent & Model

All core AI behavior and model failovers are controlled within `src/app.py`.

```python
# Modifying the System Prompt
system_prompt = "You are a Senior Network Security Analyst. Analyze the threat..."

# Modifying the IBM Granite Failover Cascade
fallback_models = [
    "ibm/granite-3-8b-instruct", 
    "ibm/granite-13b-instruct-v2", 
    "google/flan-ul2"
]

```

---

## 🔒 Security

* IBM API keys are injected via environment variables (`.env`) — never hard-coded.
* `.env` is excluded from version control (via `.gitignore`).
* All telemetry and agent communication routes through IBM's secure REST APIs.
* The Granite LLM is strictly constrained via its system prompt to only answer cybersecurity-related queries, mitigating prompt injection risks.

---

## 🏗️ Project Structure

```text
NetworkSentinelAI/
├── src/
│   ├── app.py                     # Main Gradio application & Orchestration
│   └── diagnostic_backend.py   # API validation and backend testing
├── data/
│   └── Train_data.csv      # Sample Kaggle network traffic dataset
├── requirements.txt               # Python dependencies
├── .env                           # Template for credentials
└── README.md                      # This file

```

---

## ⚕️ Disclaimer

SentinelAI is an **AI-assisted detection tool**. it is not a replacement for a human Security Operations Center (SOC) team. It is designed to augment Tier-1 analyst workflows. Always verify AI-generated mitigation playbooks against organizational security policies before execution.

---

*Built with 💙 using IBM Watson Studio · Watsonx.ai · Gradio*

```
