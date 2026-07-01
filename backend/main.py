"""
DataGuard AI — FastAPI Application
Serves the REST API at /api/* and the static frontend at /*
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

from backend.routers import upload, documents, qa, report, misc

# ── App ───────────────────────────────────────────────────────────
app = FastAPI(
    title="DataGuard AI",
    description="Sensitive Data Detection & Compliance Assistant",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API routers ────────────────────────────────────────────────────
app.include_router(upload.router,    prefix="/api", tags=["Upload"])
app.include_router(documents.router, prefix="/api", tags=["Documents"])
app.include_router(qa.router,        prefix="/api", tags=["Q&A"])
app.include_router(report.router,    prefix="/api", tags=["Report"])
app.include_router(misc.router,      prefix="/api", tags=["Misc"])

# ── Frontend static files ─────────────────────────────────────────
FRONTEND = Path("frontend")

# Serve /static/* → frontend directory (CSS, JS, assets)
app.mount(
    "/static",
    StaticFiles(directory=str(FRONTEND)),
    name="static",
)


@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(str(FRONTEND / "index.html"))


@app.get("/{full_path:path}", include_in_schema=False)
async def spa_fallback(full_path: str):
    """Serve real files if they exist; otherwise serve index.html for SPA routing."""
    target = FRONTEND / full_path
    if target.exists() and target.is_file():
        return FileResponse(str(target))
    return FileResponse(str(FRONTEND / "index.html"))
