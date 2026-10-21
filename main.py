"""
TrustMail: Application Entry Point.
Initializes FastAPI, configures SQLite database, and serves the static cybersecurity UI.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from starlette.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from trustmail.config import HOST, PORT, APP_VERSION, MAX_INPUT_BYTES, SYSTEM_NAME
from trustmail.db import init_db
from trustmail.api.routes import router as api_router

STATIC_DIR = Path(__file__).resolve().parent / "trustmail" / "static"
MAX_ANALYZE_REQUEST_BYTES = MAX_INPUT_BYTES * 6 + 8192
MAX_ANALYZE_FILE_REQUEST_BYTES = MAX_INPUT_BYTES + 8192


class AnalysisRequestSizeLimitMiddleware:
    """Bound request buffering before FastAPI parses either email intake format."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        path_limits = {
            "/api/analyze": MAX_ANALYZE_REQUEST_BYTES,
            "/api/analyze-file": MAX_ANALYZE_FILE_REQUEST_BYTES,
        }
        max_request_bytes = path_limits.get(scope.get("path"))
        if max_request_bytes is None:
            await self.app(scope, receive, send)
            return

        content_length = next(
            (value for name, value in scope.get("headers", []) if name.lower() == b"content-length"),
            None,
        )
        if content_length is not None:
            try:
                if int(content_length) > max_request_bytes:
                    await JSONResponse(
                        status_code=413,
                        content={"detail": "Analysis request exceeds the supported request size."},
                    )(scope, receive, send)
                    return
            except ValueError:
                pass  # Let the ASGI server/framework reject malformed length headers.

        received_bytes = 0
        async def limited_receive():
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > max_request_bytes:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await JSONResponse(
                status_code=413,
                content={"detail": "Analysis request exceeds the supported request size."},
            )(scope, receive, send)


class RequestBodyTooLarge(Exception):
    pass


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
app.add_middleware(AnalysisRequestSizeLimitMiddleware)

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
