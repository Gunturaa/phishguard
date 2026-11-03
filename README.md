# PHISHGUARD

Starter project: Next.js frontend + FastAPI backend. The current scan endpoint is a safe placeholder; it does not yet claim to detect phishing. ML, heuristics, and Google Web Risk will be added in later stages.

## Requirements
- Node.js 20.9+
- Python 3.11+
- npm
- Windows PowerShell (commands below also adapt to macOS/Linux)

## 1. Backend
Open PowerShell in the `PHISHGUARD` folder:

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

If PowerShell blocks activation, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Backend health check: http://127.0.0.1:8000/health  
API docs: http://127.0.0.1:8000/docs

## 2. Frontend
Open a SECOND PowerShell window in the `PHISHGUARD` folder:

```powershell
cd frontend
npm install
Copy-Item .env.example .env.local
npm run dev
```

Open http://localhost:3000

## Current functionality
- Dark cybersecurity landing page
- URL input and basic URL format validation
- Calls FastAPI `/scan` endpoint
- Displays a clearly labeled preliminary/demo response

## Important
Do not visit submitted URLs automatically. Do not send credentials, cookies, or personal data to scanned sites. The initial endpoint is only a placeholder and must not be represented as a reliable security verdict. Later stages will add:
1. URL feature extraction and a trained/evaluated ML model
2. Heuristic rules
3. Google Web Risk lookup, with API key stored only on the backend
4. Supabase scan history (optional authentication)

Never commit `.env.local`, API keys, or model/data files containing secrets.
