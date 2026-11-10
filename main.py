from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from database import init_db, get_all_vulnerabilities
from scraper import run_crawler
import uvicorn
import os
from dotenv import load_dotenv

load_dotenv()

IS_VERCEL = bool(os.environ.get("VERCEL"))
# Crawling is disabled unless CRAWL_TOKEN is set, so nobody else can spend your Gemini quota
CRAWL_TOKEN = os.environ.get("CRAWL_TOKEN")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Logic
    init_db()
    yield
    # Shutdown Logic (if needed) can go here

app = FastAPI(title="Defensive Vulnerability Intelligence Tool", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/crawl")
def trigger_crawler(
    background_tasks: BackgroundTasks,
    x_crawl_token: str | None = Header(default=None),
):
    if not CRAWL_TOKEN or x_crawl_token != CRAWL_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing crawl token.")

    if IS_VERCEL:
        # Serverless functions stop after the response, so background tasks would be killed.
        run_crawler()
        return {"status": "Crawl finished."}

    background_tasks.add_task(run_crawler)
    return {"status": "Crawler triggered. Processing in background."}

@app.get("/api/vulnerabilities")
def fetch_vulnerabilities():
    return get_all_vulnerabilities()

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def serve_dashboard():
    dashboard_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(dashboard_path):
        return FileResponse(dashboard_path)
    return {"error": "Dashboard UI not found in static folder."}

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)