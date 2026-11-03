"""
PHISHGUARD Backend Entrypoint
Mengekspor objek FastAPI 'app' dari backend.main untuk kemudahan kompatibilitas runner.
"""

from main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
