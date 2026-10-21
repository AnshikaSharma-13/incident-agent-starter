
import os
import requests

key = os.getenv("MODEL_API_KEY")
base = os.getenv("MODEL_BASE_URL", "").rstrip("/")
model = os.getenv("MODEL_NAME")

if not key:
    raise SystemExit("API key is missing. Run Step 2 again.")

response = requests.post(
    base + "/chat/completions",
    headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    },
    json={
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": 'Reply with exactly this JSON: {"ready": true}',
            }
        ],
        "response_format": {"type": "json_object"},
    },
    timeout=30,
)

print("HTTP status:", response.status_code)

if response.ok:
    print(response.json()["choices"][0]["message"]["content"])
else:
    print(response.text[:1000])
