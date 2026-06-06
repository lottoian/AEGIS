import requests

SERVER_URL = "http://localhost:8080"

print("1. Testing Log Retrieval API...")
try:
    response = requests.get(f"{SERVER_URL}/logs/testdevicepy01/SecurityTamperLog")
    print(f"Status Code: {response.status_code}")
    print(f"Response Body (First 200 chars):\n{response.text[:200]}\n")
except Exception as e:
    print(f"Error: {e}")

print("2. Testing Log Analyze (Report Generation) API...")
try:
    # 2026-06-06T00:00:00 to 2026-06-06T23:59:59
    response = requests.get(f"{SERVER_URL}/logs/analyze/testdevicepy01/2026-06-06T00:00:00/2026-06-06T23:59:59")
    print(f"Status Code: {response.status_code}")
    print(f"Response Body:\n{response.text}\n")
except Exception as e:
    print(f"Error: {e}")
