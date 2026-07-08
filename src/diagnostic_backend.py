import requests
import json
import time
from google.colab import userdata

print("🔍 Initializing NetworkSentinelAI Backend...")

# 1. Load Secrets
IBM_API_KEY = str(userdata.get("IBM_API_KEY"))
PROJECT_ID = str(userdata.get("PROJECT_ID"))
WML_ENDPOINT_URL = str(userdata.get("WML_ENDPOINT_URL"))
AGENT_ENDPOINT_URL = "https://us-south.ml.cloud.ibm.com/ml/v1/text/generation?version=2023-05-29"

# 2. Get IBM Token
print("⏳ Fetching IBM Cloud IAM Token...")
token_url = "https://iam.cloud.ibm.com/identity/token"
token_headers = {"Content-Type": "application/x-www-form-urlencoded"}
token_data = f"grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey={IBM_API_KEY}"
token_response = requests.post(token_url, headers=token_headers, data=token_data)

if token_response.status_code == 200:
    token = token_response.json()["access_token"]
    print("✅ Token Acquired Successfully.")
else:
    print(f"❌ Token Failed: {token_response.text}")
    token = None

# 3. Test Machine Learning Endpoint (Simulating an Anomaly/DoS)
if token:
    print("\n⏳ Sending network traffic payload to Watson Machine Learning...")
    wml_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    wml_payload = {
        "input_data": [{
            "fields": [
                "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
                "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", 
                "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", 
                "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", 
                "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", 
                "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
                "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", 
                "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", 
                "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
            ],
            "values": [[
                0, "tcp", "private", "S0", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
                123, 6, 1.0, 1.0, 0.0, 0.0, 0.05, 0.07, 0.0, 255, 26, 0.1, 0.05, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0
            ]]
        }]
    }
    
    wml_response = requests.post(WML_ENDPOINT_URL, json=wml_payload, headers=wml_headers)
    
    if wml_response.status_code == 200:
        prediction = wml_response.json()["predictions"][0]["values"][0][0]
        print(f"✅ ML Classification Result: **{prediction.upper()}**")
    else:
        print(f"❌ ML Endpoint Failed: {wml_response.text}")
        prediction = "anomaly"

# 4. Test Agentic AI Endpoint with Throttled Auto-Failover
if token and prediction:
    print(f"\n⏳ Sending classification ({prediction}) to Security Analyst Agent...")
    system_prompt = (
        "You are a Senior Network Security Analyst. Analyze the threat and provide a response strictly in this format:\n\n"
        "Threat Summary:\nSeverity:\nAttack Category:\nIndicators:\nImmediate Actions:\n1.\n2.\n3.\n\nLong-term Recommendations:"
    )
    user_prompt = f"Alert: Traffic flagged as {prediction}. Provide the analysis report."
    
    fallback_models = [
        "ibm/granite-3-8b-instruct",
        "ibm/granite-13b-instruct-v2",
        "google/flan-ul2"
    ]
    
    agent_success = False
    for model in fallback_models:
        print(f"   Trying foundation model: {model}...")
        agent_payload = {
            "model_id": model, 
            "input": f"System: {system_prompt}\nUser: {user_prompt}\nAssistant:",
            "parameters": {"decoding_method": "greedy", "max_new_tokens": 400},
            "project_id": PROJECT_ID
        }
        agent_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}
        
        agent_response = requests.post(AGENT_ENDPOINT_URL, json=agent_payload, headers=agent_headers)
        
        if agent_response.status_code == 200:
            print("\n✅ Agent Response Received:\n")
            print("-" * 50)
            print(agent_response.json()["results"][0]["generated_text"])
            print("-" * 50)
            agent_success = True
            break
        elif agent_response.status_code == 429:
            print(f"   ⚠️ Rate limited. Waiting 3 seconds before next attempt...")
            time.sleep(3)
        else:
            print(f"   ❌ {model} failed. Code: {agent_response.status_code}")
            time.sleep(2) # Prevent triggering rate limit on the next model
            
    if not agent_success:
        print(f"\n❌ All Agent Endpoints Failed. Last error: {agent_response.text}")
