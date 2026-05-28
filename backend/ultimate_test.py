import requests
import time
import json

BASE_URL = "http://127.0.0.1:8000/api/v1"
ADMIN_USER = {"username": "admin@aicds.com", "password": "admin123"}
TEST_URL = "https://www.wikipedia.org" # A suspicious looking URL

def run_test():
    print("🚀 Starting Ultimate Integration Test...")

    # 1. Login
    print("🔑 Logging in...")
    login_res = requests.post(f"{BASE_URL}/auth/login", data=ADMIN_USER)
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. First Scan (Creating Memory)
    print(f"\n📡 FIRST SCAN: Investigating {TEST_URL}...")
    scan1 = requests.post(f"{BASE_URL}/analysis/url", json={"url": TEST_URL}, headers=headers).json()
    task1_id = scan1["task_id"]

    # Poll until finished
    while True:
        status = requests.get(f"{BASE_URL}/analysis/status/{task1_id}", headers=headers).json()
        if status["status"] == "completed":
            print(f"✅ First Scan Result: {status['result']['verdict']} (Conf: {status['result']['confidence']}%)")
            break
        time.sleep(2)

    print("\n⏱️ Waiting 5 seconds for Vector Memory to settle...")
    time.sleep(5)

    # 3. Second Scan (Testing RAG/Memory)
    print(f"\n📡 SECOND SCAN (Same URL): Checking if AI remembers...")
    scan2 = requests.post(f"{BASE_URL}/analysis/url", json={"url": TEST_URL}, headers=headers).json()
    task2_id = scan2["task_id"]

    while True:
        status = requests.get(f"{BASE_URL}/analysis/status/{task2_id}", headers=headers).json()
        if status["status"] == "completed":
            print(f"🧠 RAG SUCCESS: AI verdict returned: {status['result']['verdict']}")
            print(f"📝 AI Reason: {status['result']['reason']}")
            break
        time.sleep(2)

if __name__ == "__main__":
    run_test()