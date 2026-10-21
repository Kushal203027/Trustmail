"""
TrustMail: Application Entry Point.
Initializes FastAPI, configures SQLite database, and serves the static cybersecurity UI.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from trustmail.config import HOST, PORT, APP_VERSION, SYSTEM_NAME
from trustmail.db import init_db
from trustmail.api.routes import router as api_router

STATIC_DIR = Path(__file__).resolve().parent / "trustmail" / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initializes persistent storage on application startup."""
    init_db()
    yield


app = FastAPI(
    title=SYSTEM_NAME,
    version=APP_VERSION,
    description="Cybersecurity platform for structured email security analysis, evidence tracking, and human-reviewed incident triage.",
    lifespan=lifespan,
)

# Include API routes
app.include_router(api_router)

# Mount static UI files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_index():
    """Serves the TrustMail cybersecurity dashboard."""
    index_file = STATIC_DIR / "index.html"
    return FileResponse(str(index_file))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=HOST, port=PORT, reload=True)
