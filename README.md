# Incident Agent starter

This is a beginner-oriented FastAPI starter for the `ga5-mailroom-action-gate/v2` assignment.

## 1. Requirements
- Python 3.11+ recommended
- An OpenAI-compatible model API key
- A persistent disk/volume for `incident_agent.sqlite3` in deployment

## 2. Run on Windows in VS Code
Open a terminal in this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:MODEL_API_KEY="YOUR_KEY_HERE"
$env:MODEL_BASE_URL="https://api.openai.com/v1"
$env:MODEL_NAME="gpt-4o-mini"
uvicorn main:app --host 127.0.0.1 --port 8000
```

Do not put a real key in source code or commit it to GitHub. If using another OpenAI-compatible provider, use its documented base URL and model name.

Open http://127.0.0.1:8000/ to confirm the server starts. This is only a local test URL, not the public HTTPS URL required by the grader.

## 3. Deployment
Deploy this folder to a Python hosting service that supports FastAPI and a persistent disk. Build command:

`pip install -r requirements.txt`

Start command:

`uvicorn main:app --host 0.0.0.0 --port $PORT`

Configure `MODEL_API_KEY`, `MODEL_BASE_URL`, and `MODEL_NAME` as host environment variables. Attach a persistent disk and set `DATABASE_PATH` to a file path on that disk. Without persistent storage, replay/cache marks can fail after restarts. Use the final public HTTPS origin only, with no query, fragment, or credentials.

## 4. Important caveats before submitting
- The service proposes actions but does not send real emails or modify customer systems. The assignment's `executed` status is derived only from a verified accepted receipt.
- This is a starter, not a guarantee of a high score. Test against the grader's feedback, especially action accuracy and minimal evidence.
- The model output is schema-validated, but the model still needs careful evaluation on dossiers. The assignment says not to rely on blanket policies or keyword-only filters.
- The code rejects invalid/mismatched signatures and uses SQLite persistence. It uses one batched model call for uncached dossiers to fit the grader's time limit.
- The public-key JWK is read from each evaluation; no key is hard-coded.
- Check that your hosting plan supports persistent SQLite storage. If not, use a persistent database.
