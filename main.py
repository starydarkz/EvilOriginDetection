"""
main.py — Evil Origin Detection — FastAPI application entry point.
Run locally:  uvicorn main:app --reload
Run in prod:  gunicorn main:app -k uvicorn.workers.UvicornWorker
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.database import init_db
from app.routers.analyze import router as analyze_router
from app.routers.results import router as results_router
from app.logger import app_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    app_logger.info("Evil Origin Detection starting up...")
    await init_db()
    app_logger.info("Database initialized.")
    yield
    app_logger.info("Evil Origin Detection shutting down.")


app = FastAPI(
    title       = "Evil Origin Detection",
    description = "Threat Intelligence Correlation Platform",
    version     = "0.1.0",
    docs_url    = None,   # Disable Swagger in production
    redoc_url   = None,
    lifespan    = lifespan,
)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(analyze_router)
app.include_router(results_router)
