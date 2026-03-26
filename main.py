from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from database import init_db, get_all_vulnerabilities
from scraper import run_crawler
import uvicorn
import os
from dotenv import load_dotenv

load_dotenv()
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup Logic
    init_db()
    if not os.path.exists("static"):
        os.makedirs("static")
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
def trigger_crawler(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_crawler)
    return {"status": "Crawler triggered. Processing in background."}

@app.get("/api/vulnerabilities")
def fetch_vulnerabilities():
    return get_all_vulnerabilities()

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def serve_dashboard():
    dashboard_path = os.path.join("static", "index.html")
    if os.path.exists(dashboard_path):
        return FileResponse(dashboard_path)
    return {"error": "Dashboard UI not found in static folder."}

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)